# Balloni API server (מפתחות API)

שרת קטן (Python בלבד, בלי התקנות) שמנפיק ומבטל מפתחות API, ונותן ממשק צ'אט תואם OpenAI לכל מי שמחזיק מפתח.
GitHub Pages הוא אתר סטטי ולכן השרת הזה רץ במקום אחר (VPS, או המחשב שלך עם Cloudflare Tunnel) ולא ב-GitHub.

## הפעלה
1. הרץ את המודל עם llama.cpp: `llama-server -m balloni-f16.gguf --port 8081`
2. הרץ את השרת:
```
set ADMIN_PASSWORD=סיסמה-ארוכה-לפחות-12-תווים
python balloni_server.py
```
3. חשוף אותו לאינטרנט **רק מאחורי HTTPS** (Caddy / nginx / Cloudflare Tunnel). ברירת המחדל מאזינה ל-127.0.0.1.
4. ניהול מפתחות: `https://הכתובת-שלך/admin` (כניסה עם סיסמת המנהל).

## שימוש (למי שקיבל מפתח)
```
curl https://הכתובת-שלך/v1/chat/completions -H "Authorization: Bearer bal-..." -H "Content-Type: application/json" \
  -d "{\"messages\":[{\"role\":\"user\",\"content\":\"שלום\"}]}"
```

## בטיחות
- אין סיסמת ברירת מחדל: בלי `ADMIN_PASSWORD` (12+ תווים) השרת לא עולה.
- מפתח = 256 ביט אקראי; נשמר רק ה-hash; מוצג פעם אחת; אפשר לבטל.
- מפתח נותן שיחה בלבד (בלי כלים/קבצים), עד 30 בקשות בדקה, עד 1024 טוקנים לתשובה.
- חסימה אחרי 5 ניסיונות שגויים (מפתח או סיסמה). תוכן השיחות לא נשמר.
