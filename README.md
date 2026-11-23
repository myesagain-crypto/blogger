# WP Plugin Insights — Blogger Bridge

Secure Flask editorial dashboard for the separate Blogger site at https://wpplugininsights.blogspot.com/.

## Deploy on Render
1. Deploy this repo as a **free** Python web service with build command `pip install -r requirements.txt` and start command `gunicorn --bind 0.0.0.0:$PORT app:app`.
2. Create a PostgreSQL database (review limits and expiry of free tier before relying on it). Put its **internal URL** in `DATABASE_URL` for the web service.
3. In Render environment settings, configure `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `BASE_URL` (the exact service HTTPS origin, without trailing slash), `ADMIN_EMAIL` (the Google account with Blogger edit access), `BLOG_URL` and `FERNET_KEY`.
4. Generate a new encryption key locally with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`; keep it private and backed up. Also set a long random `SESSION_SECRET` in Render.
5. In Google Cloud, enable Blogger API v3, configure OAuth consent and create a **Web application** OAuth client. Set the exact authorized redirect URI to `https://YOUR-RENDER-HOST.onrender.com/oauth/callback`.
6. Open the deployed app, click **Connect Google**, grant Blogger permissions as the `ADMIN_EMAIL` account, then use the private editorial dashboard to create, edit and publish posts.

## Security
- Google refresh tokens are encrypted before being stored in PostgreSQL; never commit OAuth secrets or tokens.
- Only the verified allowlisted Google email can log in; forms have CSRF protection.
- Access is browser-based and post publishing is a deliberate action. This is **not yet a ChatGPT connector or autonomous agent API**.
- Consent screen left in Google Testing mode may produce 7-day refresh-token expiry for these scopes.
- If the service runs on Render's free plan it can sleep when idle. Free PostgreSQL availability and data-retention limits can change.
- Never put secrets into GitHub files, issues, or this chat.
