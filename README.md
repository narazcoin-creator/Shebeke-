# ŞƏBƏKƏ — production-oriented full-stack MVP

This repository is the working foundation for the ŞƏBƏKƏ social network. It deliberately contains **no generated users, bots or fake posts**. A fresh database starts empty.

## Stack
- Web: React + Vite
- API: Node.js + Express
- Realtime: Socket.IO
- Database: PostgreSQL
- Auth: JWT in HttpOnly cookie + email verification code
- Media: local upload volume (swap to S3-compatible storage for production)
- Email: SMTP via Nodemailer
- AI: optional OpenAI-compatible endpoint, never creates feed posts automatically

## Run
1. Copy `.env.example` to `.env`.
2. Set a strong `JWT_SECRET`.
3. Configure real SMTP values. Registration is intentionally blocked if SMTP is not configured.
4. Optionally configure AI endpoint/key.
5. Run:
   `docker compose -f infra/docker-compose.yml up --build`
6. Open `http://localhost:3000`.

The first account is not automatically an admin. To promote an account, run:
`docker compose -f infra/docker-compose.yml exec db psql -U shebeke -d shebeke -c "UPDATE users SET role='admin' WHERE email='YOUR_EMAIL';"`

## Production
Use HTTPS, a real domain, managed PostgreSQL, object storage, Redis, a transactional email provider, secrets manager, backups, rate limiting/WAF, moderation workflows, and a separate Android build pipeline. Do not put secrets into GitHub.
