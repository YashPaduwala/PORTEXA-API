# PORTEXA Portfolio API

FastAPI service for account access and portfolio creation, management, preview, and download. Available themes are **3D Minimal** (`3d-minimal`) and **Mono Orbit** (`mono-orbit`); portfolio content stays theme-independent.

## Run locally

1. Create and activate a Python virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Configure `.env` with `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, and a long random `TOKEN_SECRET`. The MySQL database in `DB_NAME` must already exist. Set `CORS_ORIGINS` to the exact frontend origins used in development/deployment.
4. Start the service with `uvicorn main:app --reload --host 127.0.0.1 --port 8000`.
5. Open `/docs` for the interactive API reference and `/health` for the process health check.

The service connects to the existing `portfolio_ai` database using its `DB_NAME` setting. On startup it creates only `portexa_users` and `portexa_portfolios`; your existing `users`, `portfolios`, `projects`, `skills`, `education`, `experience`, `certificates`, and `achievements` tables are left untouched. Portfolio records are stored in the PORTEXA-namespaced table so its JSON document format does not conflict with your existing relational `portfolios` table. Passwords are stored as salted PBKDF2 hashes.

## Portfolio workflow

- `POST /api/auth/signup` and `POST /api/auth/login` return a Bearer access token.
- Authenticated clients can create, list, retrieve, update, and delete portfolios under `/api/portfolios`.
- `GET /api/themes` lists the available theme.
- Public portfolios can be viewed as data at `/api/public/portfolios/{id}` and downloaded as a standalone HTML website at `/api/public/portfolios/{id}/download`.

Send `Authorization: Bearer <access_token>` for account and portfolio management. Access tokens expire after seven days. Set `TOKEN_SECRET` to a stable secret so issued tokens remain valid across restarts.
