"""PORTEXA portfolio API."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from typing import Annotated
from urllib.parse import quote
from uuid import UUID, uuid4

import mysql.connector
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from database.connection import get_connection

TOKEN_SECRET = os.getenv("TOKEN_SECRET", "").encode()
TOKEN_TTL = 60 * 60 * 24 * 7
CURRENT_THEME = "3d-minimal"


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class SignupRequest(Credentials):
    name: str = Field(min_length=1, max_length=120)


class Project(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=4000)
    technologies: list[str] = Field(default_factory=list, max_length=30)
    url: str | None = Field(default=None, max_length=500)

    @field_validator("url")
    @classmethod
    def safe_project_url(cls, value: str | None) -> str | None:
        return validate_web_url(value)


class PortfolioInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    full_name: str = Field(min_length=1, max_length=120)
    role: str = Field(min_length=1, max_length=160)
    email: EmailStr | None = None
    location: str = Field(default="", max_length=160)
    bio: str = Field(default="", max_length=5000)
    skills: list[str] = Field(default_factory=list, max_length=60)
    projects: list[Project] = Field(default_factory=list, max_length=30)
    education: list[str] = Field(default_factory=list, max_length=20)
    experience: list[str] = Field(default_factory=list, max_length=30)
    github: str | None = Field(default=None, max_length=500)
    linkedin: str | None = Field(default=None, max_length=500)
    theme: str = CURRENT_THEME

    @field_validator("theme")
    @classmethod
    def only_available_theme(cls, value: str) -> str:
        if value != CURRENT_THEME:
            raise ValueError(f"Theme must be {CURRENT_THEME!r}; more themes are coming soon")
        return value

    @field_validator("github", "linkedin")
    @classmethod
    def safe_social_url(cls, value: str | None) -> str | None:
        return validate_web_url(value)


def validate_web_url(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    candidate = value if value.startswith(("https://", "http://")) else f"https://{value}"
    if not candidate.startswith(("https://", "http://")) or any(char in candidate for char in "\r\n\t\"'"):
        raise ValueError("Links must use a valid http or https address")
    return candidate


def initialize_storage() -> None:
    """Create app-owned tables; the configured database must already exist."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS portexa_users (
            id CHAR(36) PRIMARY KEY, name VARCHAR(120) NOT NULL,
            email VARCHAR(254) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS portexa_portfolios (
            id CHAR(36) PRIMARY KEY, owner_id CHAR(36) NOT NULL,
            title VARCHAR(180) NOT NULL, theme VARCHAR(80) NOT NULL,
            content JSON NOT NULL, is_public BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            CONSTRAINT fk_portexa_portfolio_owner FOREIGN KEY (owner_id) REFERENCES portexa_users(id) ON DELETE CASCADE,
            INDEX idx_portexa_portfolios_owner_updated (owner_id, updated_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
        connection.commit()
        cursor.close()
    finally:
        connection.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_storage()
    yield


app = FastAPI(
    title="PORTEXA Portfolio API",
    summary="Create, manage, preview, and download professional portfolios.",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500").split(",")],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"{salt.hex()}:{derived.hex()}"


def password_matches(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310_000)
        return hmac.compare_digest(check.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def issue_token(user_id: str) -> str:
    if not TOKEN_SECRET:
        raise HTTPException(status_code=503, detail="Set TOKEN_SECRET before issuing access tokens")
    payload = f"{user_id}.{int(time.time()) + TOKEN_TTL}"
    signature = hmac.new(TOKEN_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def current_user(authorization: Annotated[str | None, Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Sign in to continue")
    try:
        user_id, expires, signature = authorization[7:].rsplit(".", 2)
        payload = f"{user_id}.{expires}"
        expected = hmac.new(TOKEN_SECRET, payload.encode(), hashlib.sha256).hexdigest()
        UUID(user_id)
        if not TOKEN_SECRET or not hmac.compare_digest(signature, expected) or int(expires) < time.time():
            raise ValueError
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    connection = get_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email FROM portexa_users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
    finally:
        connection.close()
    if not user:
        raise HTTPException(status_code=401, detail="User account no longer exists")
    return user


def serialize_portfolio(row: dict) -> dict:
    content = row["content"]
    if isinstance(content, str):
        content = json.loads(content)
    return {
        "id": row["id"], "title": row["title"], "theme": row["theme"],
        "content": content, "is_public": bool(row["is_public"]),
        "created_at": row["created_at"].isoformat(), "updated_at": row["updated_at"].isoformat(),
    }


def portfolio_for_owner(portfolio_id: UUID, owner_id: str, public_only: bool = False) -> dict:
    connection = get_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        condition = "id = %s AND is_public = TRUE" if public_only else "id = %s AND owner_id = %s"
        values = (str(portfolio_id),) if public_only else (str(portfolio_id), owner_id)
        cursor.execute(f"SELECT * FROM portexa_portfolios WHERE {condition}", values)
        row = cursor.fetchone()
        cursor.close()
    finally:
        connection.close()
    if not row:
        raise HTTPException(status_code=404, detail="Portfolio not found")
    return serialize_portfolio(row)


@app.get("/", tags=["System"])
def root():
    return {"name": "PORTEXA Portfolio API", "docs": "/docs", "health": "/health"}


@app.get("/health", tags=["System"])
def health():
    return {"status": "ok"}


@app.get("/api/themes", tags=["Themes"])
def list_themes():
    return {"themes": [{"id": CURRENT_THEME, "name": "3D Minimal", "available": True}]}


@app.post("/api/auth/signup", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
def signup(data: SignupRequest):
    user_id = str(uuid4())
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("INSERT INTO portexa_users (id, name, email, password_hash) VALUES (%s, %s, %s, %s)",
                       (user_id, data.name, data.email.lower(), password_hash(data.password)))
        connection.commit()
        cursor.close()
    except mysql.connector.IntegrityError:
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    finally:
        connection.close()
    return {"access_token": issue_token(user_id), "token_type": "bearer", "user": {"id": user_id, "name": data.name, "email": data.email.lower()}}


@app.post("/api/auth/login", tags=["Authentication"])
def login(data: Credentials):
    connection = get_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, password_hash FROM portexa_users WHERE email = %s", (data.email.lower(),))
        user = cursor.fetchone()
        cursor.close()
    finally:
        connection.close()
    if not user or not password_matches(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    return {"access_token": issue_token(user["id"]), "token_type": "bearer", "user": {"id": user["id"], "name": user["name"], "email": user["email"]}}


@app.get("/api/auth/me", tags=["Authentication"])
def me(user: dict = Depends(current_user)):
    return {"user": user}


@app.get("/api/portfolios", tags=["Portfolios"])
def list_portfolios(user: dict = Depends(current_user), limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    connection = get_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM portexa_portfolios WHERE owner_id = %s ORDER BY updated_at DESC LIMIT %s OFFSET %s", (user["id"], limit, offset))
        rows = cursor.fetchall()
        cursor.close()
    finally:
        connection.close()
    return {"items": [serialize_portfolio(row) for row in rows], "limit": limit, "offset": offset}


@app.post("/api/portfolios", status_code=status.HTTP_201_CREATED, tags=["Portfolios"])
def create_portfolio(data: PortfolioInput, user: dict = Depends(current_user)):
    portfolio_id = str(uuid4())
    content = data.model_dump(mode="json")
    title = f"{data.full_name} — {data.role}"
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("INSERT INTO portexa_portfolios (id, owner_id, title, theme, content) VALUES (%s, %s, %s, %s, %s)",
                       (portfolio_id, user["id"], title[:180], data.theme, json.dumps(content)))
        connection.commit()
        cursor.close()
    finally:
        connection.close()
    return portfolio_for_owner(UUID(portfolio_id), user["id"])


@app.get("/api/portfolios/{portfolio_id}", tags=["Portfolios"])
def get_portfolio(portfolio_id: UUID, user: dict = Depends(current_user)):
    return portfolio_for_owner(portfolio_id, user["id"])


@app.put("/api/portfolios/{portfolio_id}", tags=["Portfolios"])
def update_portfolio(portfolio_id: UUID, data: PortfolioInput, user: dict = Depends(current_user)):
    portfolio_for_owner(portfolio_id, user["id"])
    content = data.model_dump(mode="json")
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("UPDATE portexa_portfolios SET title = %s, theme = %s, content = %s WHERE id = %s AND owner_id = %s",
                       (f"{data.full_name} — {data.role}"[:180], data.theme, json.dumps(content), str(portfolio_id), user["id"]))
        connection.commit()
        cursor.close()
    finally:
        connection.close()
    return portfolio_for_owner(portfolio_id, user["id"])


@app.delete("/api/portfolios/{portfolio_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Portfolios"])
def delete_portfolio(portfolio_id: UUID, user: dict = Depends(current_user)):
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM portexa_portfolios WHERE id = %s AND owner_id = %s", (str(portfolio_id), user["id"]))
        deleted = cursor.rowcount
        connection.commit()
        cursor.close()
    finally:
        connection.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Portfolio not found")


def render_portfolio_html(portfolio: dict) -> str:
    """Return a self-contained, responsive 3D-minimal portfolio website."""
    data = portfolio["content"]
    esc = lambda value: html.escape(str(value or ""), quote=True)
    skills = "".join(f'<span class="chip">{esc(item)}</span>' for item in data.get("skills", []))
    project_cards = []
    for item in data.get("projects", []):
        technologies = "".join('<span class="chip">' + esc(tag) + "</span>" for tag in item.get("technologies", []))
        project_cards.append(f'<article class="project"><h3>{esc(item.get("title"))}</h3><p>{esc(item.get("description"))}</p><div class="chips">{technologies}</div></article>')
    projects = "".join(project_cards)
    links = "".join(f'<a href="{esc(data[key])}" rel="noreferrer" target="_blank">{label} ↗</a>' for key, label in (("github", "GitHub"), ("linkedin", "LinkedIn")) if data.get(key))
    education = "".join(f"<li>{esc(item)}</li>" for item in data.get("education", []))
    experience = "".join(f"<li>{esc(item)}</li>" for item in data.get("experience", []))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="{esc(data.get('bio'))}"><title>{esc(data.get('full_name'))} — Portfolio</title><style>
*{{box-sizing:border-box}}:root{{--ink:#eef1f8;--muted:#aab2c4;--accent:#83e4d1}}body{{margin:0;background:radial-gradient(ellipse at 75% 10%,#263c50 0,transparent 42%),#0b0e14;color:var(--ink);font:16px/1.65 Inter,ui-sans-serif,system-ui,sans-serif}}main{{width:min(1080px,calc(100% - 40px));margin:auto}}header{{min-height:80vh;display:flex;flex-direction:column;justify-content:center;position:relative;padding:70px 0}}.orb{{position:absolute;z-index:-1;width:260px;height:260px;right:9%;top:22%;border-radius:42%;background:linear-gradient(145deg,#7ce5ce,#5b79c8 55%,#262d62);box-shadow:inset -18px -20px 35px #101526, inset 12px 14px 28px #e1fff755,0 55px 90px #0009;transform:rotate(-25deg) perspective(500px) rotateY(-25deg);filter:saturate(.8)}}.eyebrow{{color:var(--accent);text-transform:uppercase;letter-spacing:.18em;font-size:.78rem}}h1{{font-size:clamp(3rem,9vw,7rem);line-height:.98;letter-spacing:-.07em;max-width:800px;margin:.2em 0}}.role{{font-size:clamp(1.2rem,3vw,2rem);color:#c3cada}}.location,.muted{{color:var(--muted)}}.links{{display:flex;gap:18px;flex-wrap:wrap;margin-top:25px}}a{{color:var(--accent);text-decoration:none}}section{{padding:60px 0;border-top:1px solid #ffffff19}}h2{{font-size:1rem;text-transform:uppercase;letter-spacing:.16em;color:var(--accent)}}.bio{{max-width:760px;font-size:1.3rem;color:#d2d7e2}}.chips{{display:flex;gap:9px;flex-wrap:wrap}}.chip{{border:1px solid #ffffff22;background:linear-gradient(140deg,#ffffff12,#ffffff04);border-radius:999px;padding:7px 13px;color:#d4dbea}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:17px}}.project{{padding:24px;border:1px solid #ffffff1b;border-radius:20px;background:linear-gradient(145deg,#ffffff0d,#ffffff03);box-shadow:12px 14px 30px #0003}}.project h3{{margin-top:0}}ul{{padding-left:20px;color:#d2d7e2}}footer{{padding:35px 0;color:var(--muted)}}@media(max-width:650px){{.orb{{width:160px;height:160px;right:0;top:14%}}header{{min-height:72vh}}}}
</style></head><body><main><header><div class="orb" aria-hidden="true"></div><h1>{esc(data.get('full_name'))}</h1><div class="role">{esc(data.get('role'))}</div><p class="location">{esc(data.get('location'))}{' · ' if data.get('location') and data.get('email') else ''}{esc(data.get('email'))}</p><nav class="links">{links}</nav></header>{'<section><h2>About</h2><p class="bio">'+esc(data.get('bio'))+'</p></section>' if data.get('bio') else ''}{'<section><h2>Selected work</h2><div class="grid">'+projects+'</div></section>' if projects else ''}{'<section><h2>Skills</h2><div class="chips">'+skills+'</div></section>' if skills else ''}{'<section><h2>Experience</h2><ul>'+experience+'</ul></section>' if experience else ''}{'<section><h2>Education</h2><ul>'+education+'</ul></section>' if education else ''}<footer>Designed with PORTEXA</footer></main></body></html>'''


@app.get("/api/public/portfolios/{portfolio_id}", tags=["Public portfolios"])
def public_portfolio(portfolio_id: UUID):
    return portfolio_for_owner(portfolio_id, "", public_only=True)


@app.get("/api/public/portfolios/{portfolio_id}/site", tags=["Public portfolios"])
def view_portfolio_site(portfolio_id: UUID):
    portfolio = portfolio_for_owner(portfolio_id, "", public_only=True)
    return Response(render_portfolio_html(portfolio), media_type="text/html")


@app.get("/api/public/portfolios/{portfolio_id}/download", tags=["Public portfolios"])
def download_portfolio(portfolio_id: UUID):
    portfolio = portfolio_for_owner(portfolio_id, "", public_only=True)
    title = portfolio["title"]
    ascii_stem = re.sub(r"[^A-Za-z0-9_-]+", "-", title).strip("-_").lower()[:70] or "portfolio"
    utf8_filename = quote(f"{title}.html", safe="")
    return Response(
        render_portfolio_html(portfolio),
        media_type="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="{ascii_stem}.html"; filename*=UTF-8\'\'{utf8_filename}'
        },
    )
