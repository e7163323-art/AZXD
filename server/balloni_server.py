#!/usr/bin/env python3
"""Balloni API server: issues/revokes API keys and serves an OpenAI-compatible chat API to key holders.
Python standard library only. Put it behind HTTPS (Caddy / nginx / Cloudflare) before exposing it to the internet.

Environment:
  ADMIN_PASSWORD   required, at least 12 characters (no default - the server refuses to start without it)
  UPSTREAM         the llama.cpp server that runs the model (default http://127.0.0.1:8081)
  DATA_DIR         where keys are stored (default ./data)
  PORT             default 8090
  BIND             default 127.0.0.1 (use a reverse proxy; set 0.0.0.0 only if you know why)

Safety: keys are 256-bit random and only their SHA-256 hash is stored (shown once at creation); a key can only call
/v1/chat/completions and /v1/models (plain chat, allow-listed fields, bounded size); per-key rate limit; per-IP lockout
after repeated bad keys / bad admin passwords; message content is never logged.
"""
import hashlib, hmac, json, os, secrets, threading, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
UPSTREAM = os.environ.get("UPSTREAM", "http://127.0.0.1:8081").rstrip("/")
DATA_DIR = os.environ.get("DATA_DIR", "data")
PORT = int(os.environ.get("PORT", "8090"))
BIND = os.environ.get("BIND", "127.0.0.1")
MAX_BODY = 1 << 20
PER_MINUTE = 30
MAX_KEYS = 50
CORS = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Max-Age": "600"}

lock = threading.Lock()
os.makedirs(DATA_DIR, exist_ok=True)
KEYS_FILE = os.path.join(DATA_DIR, "keys.json")
LOG_FILE = os.path.join(DATA_DIR, "usage.log")
sessions = {}           # admin session token -> expiry
fails = {}              # ip -> (count, last)
hits = {}               # key id -> [timestamps]
api_gate = threading.Semaphore(2)


def load_keys():
    try:
        with open(KEYS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_keys(keys):
    tmp = KEYS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(keys, f, ensure_ascii=False, indent=1)
    os.replace(tmp, KEYS_FILE)


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def log(line):
    with lock, open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S  ") + line.replace("\n", " ") + "\n")


def locked(ip):
    c = fails.get(ip)
    return bool(c and c[0] >= 5 and time.time() - c[1] < 900)


def fail(ip):
    c = fails.get(ip)
    fails[ip] = (1 if not c or time.time() - c[1] >= 900 else c[0] + 1, time.time())


def create_key(label):
    with lock:
        keys = load_keys()
        if sum(1 for k in keys if not k.get("revoked")) >= MAX_KEYS:
            return None
        key = "bal-" + secrets.token_hex(32)
        keys.append({"id": secrets.token_hex(4), "label": (label or "key")[:40], "hash": sha(key),
                     "created": time.strftime("%Y-%m-%d %H:%M"), "last": "", "requests": 0, "revoked": False})
        save_keys(keys)
        return key


def validate(bearer):
    if not bearer.startswith("bal-") or len(bearer) > 200:
        return None
    h = sha(bearer)
    with lock:
        keys = load_keys()
        found = None
        for k in keys:
            if hmac.compare_digest(k["hash"], h) and not k.get("revoked"):
                found = k
        if found:
            found["requests"] += 1
            found["last"] = time.strftime("%Y-%m-%d %H:%M")
            save_keys(keys)
        return found


def rate_ok(kid):
    now = time.time()
    q = [t for t in hits.get(kid, []) if now - t < 60]
    if len(q) >= PER_MINUTE:
        hits[kid] = q
        return False
    q.append(now)
    hits[kid] = q
    return True


ADMIN_HTML = """<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Balloni - מפתחות API</title><style>
body{font-family:Segoe UI,Arial;max-width:720px;margin:40px auto;padding:0 16px;color:#1f1f1d}h1{margin:0 0 4px}
table{width:100%;border-collapse:collapse;margin:16px 0}td,th{padding:8px;border-bottom:1px solid #e5e3dd;text-align:start}
button,input{font:inherit;padding:8px 14px;border-radius:10px;border:1px solid #ccc}button.p{background:#e5484d;color:#fff;border:0;cursor:pointer}
code{direction:ltr;unicode-bidi:embed;background:#f0efeb;padding:2px 6px;border-radius:6px;word-break:break-all}.k{background:#fff7e6;border:1px solid #f0c36d;padding:12px;border-radius:10px;margin:12px 0}
</style><body><h1>🎈 מפתחות API</h1><p>מי שמחזיק מפתח יכול לשוחח עם ה-AI (שיחה בלבד).</p>
<div id="app"></div><script>
async function api(p,b){const r=await fetch(p,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b||{})});return r.json()}
async function render(){const d=await api("/admin/list");const a=document.getElementById("app");
if(d.error){a.innerHTML='<input id=pw type=password placeholder="סיסמת מנהל"> <button class=p onclick=login()>כניסה</button>';return}
a.innerHTML='<input id=lb placeholder="שם למפתח"> <button class=p onclick=mk()>מפתח חדש</button><div id=nk></div><table><tr><th>שם<th>נוצר<th>שימוש אחרון<th>בקשות<th>מצב<th></tr>'+d.keys.map(k=>'<tr><td>'+esc(k.label)+'<td>'+k.created+'<td>'+(k.last||"—")+'<td>'+k.requests+'<td>'+(k.revoked?"מבוטל":"פעיל")+'<td>'+(k.revoked?"":'<button onclick="rv(\\''+k.id+'\\')">בטל</button>')).join("")+'</table><p>כתובת: <code>'+location.origin+'/v1</code> · כותרת: <code>Authorization: Bearer &lt;המפתח&gt;</code></p>'}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
async function login(){const d=await api("/admin/login",{password:document.getElementById("pw").value});if(d.error)alert(d.error);render()}
async function mk(){const d=await api("/admin/create",{label:document.getElementById("lb").value});if(d.error){alert(d.error);return}await render();document.getElementById("nk").innerHTML='<div class=k>העתק עכשיו - המפתח מוצג פעם אחת בלבד:<br><code>'+d.key+'</code></div>'}
async function rv(id){if(confirm("לבטל את המפתח?")){await api("/admin/revoke",{id});render()}}
render()</script></body></html>"""


class H(BaseHTTPRequestHandler):
    server_version = "Balloni"
    sys_version = ""

    def log_message(self, *a):
        pass

    def ip(self):
        return self.client_address[0]

    def send(self, code, body=b"", ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def err(self, code, msg, extra=None):
        self.send(code, {"error": {"message": msg}}, extra=extra if extra is not None else CORS)

    def body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if n < 0 or n > MAX_BODY:
            return None
        return self.rfile.read(n)

    def admin_ok(self):
        c = self.headers.get("Cookie", "")
        tok = ""
        for p in c.split(";"):
            p = p.strip()
            if p.startswith("bal_admin="):
                tok = p[10:]
        exp = sessions.get(tok)
        return bool(exp and exp > time.time())

    def do_OPTIONS(self):
        if self.path.startswith("/v1/"):
            self.send(204, b"", "text/plain", CORS)
        else:
            self.send(404, b"", "text/plain")

    def do_GET(self):
        if self.path == "/admin" or self.path == "/admin/":
            self.send(200, ADMIN_HTML, "text/html; charset=utf-8", {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'"})
        elif self.path == "/v1/models":
            k = self.auth()
            if k:
                self.send(200, {"object": "list", "data": [{"id": "balloni", "object": "model", "owned_by": "local"}]}, extra=CORS)
        elif self.path == "/healthz":
            self.send(200, {"ok": True})
        else:
            self.send(404, b"not found", "text/plain")

    def auth(self):
        ip = self.ip()
        if locked(ip):
            self.err(429, "locked, try later")
            return None
        h = self.headers.get("Authorization", "")
        k = validate(h[7:].strip()) if h.lower().startswith("bearer ") else None
        if not k:
            fail(ip)
            self.err(401, "invalid api key")
            return None
        if not rate_ok(k["id"]):
            self.err(429, "rate limit: %d requests per minute" % PER_MINUTE)
            return None
        return k

    def do_POST(self):
        p = self.path
        if p.startswith("/admin/"):
            return self.admin(p)
        if p != "/v1/chat/completions":
            return self.err(404, "not found")
        k = self.auth()
        if not k:
            return
        raw = self.body()
        try:
            req = json.loads(raw)
            msgs = req["messages"]
            assert isinstance(msgs, list) and 1 <= len(msgs) <= 64
        except Exception:
            return self.err(400, "messages required (1-64)")
        safe = {"messages": msgs, "stream": bool(req.get("stream", False))}
        try:
            safe["max_tokens"] = max(1, min(1024, int(req.get("max_tokens", 512))))
            if "temperature" in req:
                safe["temperature"] = max(0.0, min(2.0, float(req["temperature"])))
            if "top_p" in req:
                safe["top_p"] = max(0.0, min(1.0, float(req["top_p"])))
        except (TypeError, ValueError):
            return self.err(400, "bad parameters")
        if not api_gate.acquire(blocking=False):
            return self.err(503, "busy, try again")
        try:
            log("key %s (%s) from %s%s" % (k["id"], k["label"], self.ip(), " stream" if safe["stream"] else ""))
            rq = urllib.request.Request(UPSTREAM + "/v1/chat/completions", json.dumps(safe).encode(), {"Content-Type": "application/json"})
            with urllib.request.urlopen(rq, timeout=600) as r:
                if safe["stream"]:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    for a, b in CORS.items():
                        self.send_header(a, b)
                    self.send_header("Connection", "close")
                    self.end_headers()
                    while True:
                        c = r.read1(4096) if hasattr(r, "read1") else r.read(4096)
                        if not c:
                            break
                        self.wfile.write(c)
                        self.wfile.flush()
                    self.close_connection = True
                else:
                    self.send(200, r.read(4 << 20), extra=CORS)
        except Exception:
            try:
                self.err(502, "model server error")
            except Exception:
                pass
        finally:
            api_gate.release()

    def admin(self, p):
        ip = self.ip()
        raw = self.body()
        try:
            d = json.loads(raw or b"{}")
        except Exception:
            return self.send(400, {"error": "bad json"})
        if p == "/admin/login":
            if locked(ip):
                return self.send(429, {"error": "נחסם זמנית"})
            if ADMIN_PASSWORD and hmac.compare_digest(str(d.get("password", "")).encode(), ADMIN_PASSWORD.encode()):
                tok = secrets.token_hex(32)
                sessions[tok] = time.time() + 3600
                return self.send(200, {"ok": True}, extra={"Set-Cookie": "bal_admin=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600%s" % (tok, "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else "")})
            fail(ip)
            return self.send(403, {"error": "סיסמה שגויה"})
        # all other admin calls need the session AND a same-origin request (CSRF)
        origin = self.headers.get("Origin", "")
        host = self.headers.get("Host", "")
        if origin and not origin.endswith("//" + host):
            return self.send(403, {"error": "bad origin"})
        if not self.admin_ok():
            return self.send(401, {"error": "login"})
        if p == "/admin/list":
            ks = [{k: v for k, v in x.items() if k != "hash"} for x in load_keys()]
            return self.send(200, {"keys": ks})
        if p == "/admin/create":
            key = create_key(str(d.get("label", "")))
            if not key:
                return self.send(400, {"error": "עד %d מפתחות פעילים" % MAX_KEYS})
            log("created key (%s)" % str(d.get("label", ""))[:40])
            return self.send(200, {"key": key})
        if p == "/admin/revoke":
            with lock:
                keys = load_keys()
                for k in keys:
                    if k["id"] == d.get("id"):
                        k["revoked"] = True
                save_keys(keys)
            log("revoked key %s" % d.get("id"))
            return self.send(200, {"ok": True})
        self.send(404, {"error": "not found"})


if __name__ == "__main__":
    if len(ADMIN_PASSWORD) < 12:
        raise SystemExit("Set ADMIN_PASSWORD (at least 12 characters) before starting.")
    print("Balloni API server on http://%s:%d  (admin: /admin)  upstream: %s" % (BIND, PORT, UPSTREAM))
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()
