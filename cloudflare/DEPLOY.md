# Balloni API בלי שום מחשב דלוק (Cloudflare Workers)

הכול רץ אצל Cloudflare, בחינם בגבולות המכסה. הדף /admin יוצר ומבטל מפתחות.
**המודל הוא מודל פתוח שמארח Cloudflare (Llama 3.1 8B), לא Balloni עצמו**, כי Balloni אי אפשר להריץ ב-Workers.

נדרש: חשבון Cloudflare חינמי + Node.js על המחשב (פעם אחת, רק להעלאה).
```
npm i -g wrangler
wrangler login
wrangler kv namespace create KEYS      # העתק את ה-id לתוך wrangler.toml
wrangler secret put ADMIN_PASSWORD     # 12+ תווים
wrangler secret put SESSION_SECRET     # מחרוזת אקראית ארוכה
wrangler deploy
```
בסוף מתקבלת כתובת `https://balloni-api.<שלך>.workers.dev` - שם `/admin` לניהול מפתחות ו-`/v1/chat/completions` לשימוש.
