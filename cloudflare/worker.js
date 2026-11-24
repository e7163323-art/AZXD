// Balloni API on Cloudflare Workers: no computer to keep running. Admin page creates/revokes API keys; key holders call an OpenAI-compatible chat API.
// The model is a Cloudflare-hosted open model (Workers AI), not Balloni itself. Secrets: ADMIN_PASSWORD (12+ chars) and SESSION_SECRET (random, 32+ chars).
const MODEL = "@cf/qwen/qwen2.5-coder-32b-instruct";
const PER_MINUTE = 30, MAX_KEYS = 600, MAX_USERS = 500, MAX_BODY = 1 << 20;
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Authorization, Content-Type", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Max-Age": "600" };
const SEC = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" };
const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const sha = async s => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const json = (o, status = 200, extra = {}) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...SEC, ...extra } });
const apiErr = (status, message) => json({ error: { message } }, status, CORS);
async function hmac(secret, msg) { const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); return hex(await crypto.subtle.sign("HMAC", k, enc.encode(msg))); }
const same = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const now16 = () => new Date().toISOString().slice(0, 16).replace("T", " ");

async function locked(env, ip) { return parseInt(await env.KEYS.get("f:" + ip) || "0") >= 5; }
async function fail(env, ip) { const v = parseInt(await env.KEYS.get("f:" + ip) || "0"); await env.KEYS.put("f:" + ip, String(v + 1), { expirationTtl: 900 }); }

async function adminOk(req, env) {
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) return false;
  const m = /(?:^|;\s*)bal_admin=([0-9]+)\.([0-9a-f]+)/.exec(req.headers.get("Cookie") || "");
  if (!m || Number(m[1]) < Date.now()) return false;
  return same(m[2], await hmac(env.SESSION_SECRET, "admin." + m[1]));
}
async function listKeys(env) { const l = await env.KEYS.list({ prefix: "k:", limit: 40 }); const out = []; for (const k of l.keys) { const v = await env.KEYS.get(k.name, "json"); if (v) out.push(v); } return out; }
async function countKeys(env, prefix) { let n = 0, cursor; do { const l = await env.KEYS.list({ prefix, cursor }); n += l.keys.length; cursor = l.list_complete ? null : l.cursor; } while (cursor); return n; }

async function admin(req, env, url) {
  const ip = req.headers.get("CF-Connecting-IP") || "?";
  let d = {}; try { d = await req.json(); } catch {}
  if (url.pathname === "/admin/login") {
    if (await locked(env, ip)) return json({ error: "נחסם זמנית" }, 429);
    if (env.ADMIN_PASSWORD && env.ADMIN_PASSWORD.length >= 12 && env.SESSION_SECRET && env.SESSION_SECRET.length >= 32 && same(String(d.password || ""), env.ADMIN_PASSWORD)) {
      const exp = String(Date.now() + 3600e3);
      return json({ ok: true }, 200, { "Set-Cookie": `bal_admin=${exp}.${await hmac(env.SESSION_SECRET, "admin." + exp)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600` });
    }
    await fail(env, ip); return json({ error: "סיסמה שגויה" }, 403);
  }
  const origin = req.headers.get("Origin"); if (origin && origin !== url.origin) return json({ error: "bad origin" }, 403);   // CSRF
  if (!(await adminOk(req, env))) return json({ error: "login" }, 401);
  if (url.pathname === "/admin/list") return json({ keys: (await listKeys(env)).map(({ hash, ...k }) => k) });
  if (url.pathname === "/admin/create") {
    if ((await countKeys(env, "k:")) >= MAX_KEYS) return json({ error: "עד " + MAX_KEYS + " מפתחות פעילים" }, 400);
    const key = "bal-" + rnd(32), h = await sha(key);
    await env.KEYS.put("k:" + h, JSON.stringify({ id: rnd(4), hash: h, label: String(d.label || "key").slice(0, 40), created: now16(), last: "", requests: 0, revoked: false }));
    return json({ key });
  }
  if (url.pathname === "/admin/revoke") {
    for (const k of await listKeys(env)) if (k.id === d.id) { k.revoked = true; await env.KEYS.put("k:" + k.hash, JSON.stringify(k)); }
    return json({ ok: true });
  }
  return json({ error: "not found" }, 404);
}

async function authKey(req, env) {
  const ip = req.headers.get("CF-Connecting-IP") || "?";
  if (await locked(env, ip)) return [null, apiErr(429, "locked, try later")];
  const h = req.headers.get("Authorization") || "";
  const key = /^bearer /i.test(h) ? h.slice(7).trim() : "";
  const rec = key.startsWith("bal-") && key.length <= 200 ? await env.KEYS.get("k:" + await sha(key), "json") : null;
  if (!rec || rec.revoked) { await fail(env, ip); return [null, apiErr(401, "invalid api key")]; }
  const minute = Math.floor(Date.now() / 60000), rk = `r:${rec.id}:${minute}`, n = parseInt(await env.KEYS.get(rk) || "0");
  if (n >= PER_MINUTE) return [null, apiErr(429, `rate limit: ${PER_MINUTE} requests per minute`)];
  await env.KEYS.put(rk, String(n + 1), { expirationTtl: 120 });
  rec.requests++; if (rec.requests % 10 === 1) { rec.last = now16(); await env.KEYS.put("k:" + rec.hash, JSON.stringify(rec)); }
  return [rec, null];
}

async function chat(req, env) {
  const [rec, err] = await authKey(req, env); if (err) return err;
  const raw = await req.text(); if (raw.length > MAX_BODY) return apiErr(413, "too large");
  let b; try { b = JSON.parse(raw); } catch { return apiErr(400, "bad json"); }
  if (!Array.isArray(b.messages) || b.messages.length < 1 || b.messages.length > 64) return apiErr(400, "messages required (1-64)");
  const messages = b.messages.map(m => ({ role: ["system", "user", "assistant"].includes(m.role) ? m.role : "user", content: String(typeof m.content === "string" ? m.content : "").slice(0, 8000) }));
  const max_tokens = Math.max(1, Math.min(1024, parseInt(b.max_tokens) || 512));
  const stream = b.stream === true;
  try {
    const out = await env.AI.run(MODEL, { messages, max_tokens, stream });
    if (!stream) return json({ object: "chat.completion", model: "balloni-cloud", choices: [{ index: 0, message: { role: "assistant", content: out.response || "" }, finish_reason: "stop" }] }, 200, CORS);
    // Workers AI SSE ({"response":"x"}) -> OpenAI SSE chunks
    const dec = new TextDecoder(); let buf = "";
    const ts = new TransformStream({
      transform(chunk, ctl) {
        buf += dec.decode(chunk, { stream: true }); let i;
        while ((i = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
          if (!line.startsWith("data:")) continue; const d = line.slice(5).trim();
          if (d === "[DONE]") { ctl.enqueue(enc.encode("data: [DONE]\n\n")); continue; }
          try { const t = JSON.parse(d).response; if (t) ctl.enqueue(enc.encode("data: " + JSON.stringify({ object: "chat.completion.chunk", choices: [{ index: 0, delta: { content: t } }] }) + "\n\n")); } catch {}
        }
      }
    });
    return new Response(out.pipeThrough(ts), { headers: { "Content-Type": "text/event-stream", ...SEC, ...CORS } });
  } catch (e) { return apiErr(502, "model error: " + String(e && e.message || e).slice(0, 300)); }
}


// ---- self-service keys for visitors who sign in with Google (ID token verified here; one active key per Google account) ----
let jwks = null, jwksAt = 0;
async function googleKeys() { if (jwks && Date.now() - jwksAt < 3600e3) return jwks; const r = await fetch("https://www.googleapis.com/oauth2/v3/certs"); jwks = (await r.json()).keys; jwksAt = Date.now(); return jwks; }
const b64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), ch => ch.charCodeAt(0));
async function verifyGoogle(token, env) {
  try {
    const parts = String(token || "").split("."); if (parts.length !== 3 || token.length > 4000) return null;
    const header = JSON.parse(new TextDecoder().decode(b64u(parts[0]))); if (header.alg !== "RS256") return null;
    const jwk = (await googleKeys()).find(x => x.kid === header.kid); if (!jwk) return null;
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    if (!(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64u(parts[2]), enc.encode(parts[0] + "." + parts[1])))) return null;
    const p = JSON.parse(new TextDecoder().decode(b64u(parts[1])));
    if (!["https://accounts.google.com", "accounts.google.com"].includes(p.iss)) return null;
    if (p.aud !== env.GOOGLE_CLIENT_ID || !(p.exp * 1000 > Date.now()) || p.email_verified !== true || !p.sub) return null;
    return p;
  } catch { return null; }
}
async function userKey(req, env) {
  const cors = { "Access-Control-Allow-Origin": env.SITE_ORIGIN || "null", "Vary": "Origin", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "POST, OPTIONS", ...SEC };
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (!env.GOOGLE_CLIENT_ID || !env.SITE_ORIGIN || req.headers.get("Origin") !== env.SITE_ORIGIN) return json({ error: "origin not allowed" }, 403, cors);
  let b = {}; try { b = await req.json(); } catch {}
  const p = await verifyGoogle(b.id_token, env); if (!p) return json({ error: "התחברות Google לא תקינה" }, 401, cors);
  const uk = "u:" + p.sub, u = (await env.KEYS.get(uk, "json")) || { count: 0, day: "" };
  const today = new Date().toISOString().slice(0, 10); if (u.day !== today) { u.day = today; u.count = 0; }
  const revokeOld = async () => { if (u.hash) { const old = await env.KEYS.get("k:" + u.hash, "json"); if (old) { old.revoked = true; await env.KEYS.put("k:" + u.hash, JSON.stringify(old)); } } };
  if (b.action === "revoke") { await revokeOld(); u.hash = ""; await env.KEYS.put(uk, JSON.stringify(u)); return json({ ok: true }, 200, cors); }
  if (u.count >= 5) return json({ error: "יותר מדי מפתחות היום, נסה מחר" }, 429, cors);
  if (!u.hash && (await countKeys(env, "u:")) >= MAX_USERS) return json({ error: "הגענו למקסימום משתמשים" }, 503, cors);
  await revokeOld();
  const key = "bal-" + rnd(32), h = await sha(key);
  await env.KEYS.put("k:" + h, JSON.stringify({ id: rnd(4), hash: h, label: String(p.email).slice(0, 40), created: now16(), last: "", requests: 0, revoked: false }));
  u.hash = h; u.email = p.email; u.count++; await env.KEYS.put(uk, JSON.stringify(u));
  return json({ key, email: p.email }, 200, cors);
}

const PAGE = `<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Balloni - מפתחות API</title>
<style>body{font-family:Segoe UI,Arial;max-width:720px;margin:40px auto;padding:0 16px;color:#1f1f1d}table{width:100%;border-collapse:collapse;margin:16px 0}td,th{padding:8px;border-bottom:1px solid #e5e3dd;text-align:start}button,input{font:inherit;padding:8px 14px;border-radius:10px;border:1px solid #ccc}button.p{background:#e5484d;color:#fff;border:0;cursor:pointer}code{direction:ltr;unicode-bidi:embed;background:#f0efeb;padding:2px 6px;border-radius:6px;word-break:break-all}.k{background:#fff7e6;border:1px solid #f0c36d;padding:12px;border-radius:10px;margin:12px 0}</style>
<body><h1>🎈 מפתחות API</h1><p>מי שמחזיק מפתח יכול לשוחח עם ה-AI (שיחה בלבד).</p><div id="app"></div><script>
async function api(p,b){const r=await fetch(p,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b||{})});return r.json()}
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function render(){const d=await api("/admin/list"),a=document.getElementById("app");
if(d.error){a.innerHTML='<input id=pw type=password placeholder="סיסמת מנהל"> <button class=p onclick=login()>כניסה</button>';return}
a.innerHTML='<input id=lb placeholder="שם למפתח"> <button class=p onclick=mk()>מפתח חדש</button><div id=nk></div><table><tr><th>שם<th>נוצר<th>שימוש אחרון<th>בקשות<th>מצב<th></tr>'+d.keys.map(k=>'<tr><td>'+esc(k.label)+'<td>'+k.created+'<td>'+(k.last||"—")+'<td>'+k.requests+'<td>'+(k.revoked?"מבוטל":"פעיל")+'<td>'+(k.revoked?"":'<button data-id="'+esc(k.id)+'" onclick="rv(this.dataset.id)">בטל</button>')).join("")+'</table><p>כתובת: <code>'+location.origin+'/v1</code> · כותרת: <code>Authorization: Bearer &lt;המפתח&gt;</code></p>'}
async function login(){const d=await api("/admin/login",{password:document.getElementById("pw").value});if(d.error)alert(d.error);render()}
async function mk(){const d=await api("/admin/create",{label:document.getElementById("lb").value});if(d.error){alert(d.error);return}await render();document.getElementById("nk").innerHTML='<div class=k>העתק עכשיו - המפתח מוצג פעם אחת בלבד:<br><code>'+esc(d.key)+'</code></div>'}
async function rv(id){if(confirm("לבטל את המפתח?")){await api("/admin/revoke",{id});render()}}
render()</script></body></html>`;

export default {
  async fetch(req, env) {
    const url = new URL(req.url), p = url.pathname;
    if (req.method === "OPTIONS" && p.startsWith("/v1/")) return new Response(null, { status: 204, headers: { ...SEC, ...CORS } });
    if (p === "/admin" || p === "/admin/") return new Response(PAGE, { headers: { "Content-Type": "text/html; charset=utf-8", ...SEC, "Content-Security-Policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'" } });
    if (p === "/user/key") return userKey(req, env);
    if (p.startsWith("/admin/") && req.method === "POST") return admin(req, env, url);
    if (p === "/v1/models" && req.method === "GET") { const [r, e] = await authKey(req, env); return e || json({ object: "list", data: [{ id: "balloni-cloud", object: "model", owned_by: "cloudflare" }] }, 200, CORS); }
    if (p === "/v1/chat/completions" && req.method === "POST") return chat(req, env);
    return new Response("not found", { status: 404, headers: SEC });
  }
};
