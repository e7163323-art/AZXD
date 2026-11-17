# העלאה לענן (VPS עם Docker)

מתאים לכל שרת לינוקס עם Docker (Oracle Cloud Always Free, Hetzner, DigitalOcean וכו'; מומלץ 2 ליבות ו-2GB זיכרון לפחות).

```
git clone <הריפו שלך> && cd <הריפו>/server
mkdir models && cd models
curl -LO https://e7163323-art.github.io/AZXD/model/balloni-00001-of-00002.gguf
curl -LO https://e7163323-art.github.io/AZXD/model/balloni-00002-of-00002.gguf
cd ..
cp .env.example .env     # ערוך: ADMIN_PASSWORD (12+ תווים, אקראי) ו-DOMAIN
docker compose up -d --build
```

- `DOMAIN`: דומיין שמצביע לכתובת ה-IP של השרת. אין דומיין? השתמש ב-`<ה-IP-עם-מקפים>.sslip.io`, למשל `1-2-3-4.sslip.io`.
- ניהול מפתחות: `https://DOMAIN/admin`. API: `https://DOMAIN/v1/chat/completions` (כותרת `Authorization: Bearer bal-...`).
- רק Caddy חשוף לאינטרנט (פורטים 80/443); המודל ושרת המפתחות פנימיים. HTTPS אוטומטי.
- הדלק firewall: פתח רק 22 (SSH), 80, 443.
