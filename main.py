import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Cookie, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

DB_PATH = os.getenv("DB_PATH", "/tmp/messages.db")

USERS = {
    "robin": {"emoji": "\U0001f9d1\u200d\u2695\ufe0f", "color": "#38bdf8"},
    "papa": {"emoji": "\U0001f474", "color": "#fb923c"},
    "jarvis": {"emoji": "\U0001f916", "color": "#a78bfa"},
    "bolla": {"emoji": "\U0001f43e", "color": "#34d399"},
}

HUMAN_USERS = {"robin", "papa"}
BOT_USERS = {"jarvis", "bolla"}

sessions: dict[str, dict] = {}
last_active: dict[str, float] = {}
ws_clients: list[WebSocket] = []


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _get_passwords() -> dict[str, str]:
    return {
        "robin": _hash_password(os.getenv("ROBIN_PASSWORD", "robin123")),
        "papa": _hash_password(os.getenv("PAPA_PASSWORD", "papa123")),
    }


def _get_api_keys() -> dict[str, str]:
    return {
        os.getenv("JARVIS_API_KEY", "jarvis-default-key"): "jarvis",
        os.getenv("BOLLA_API_KEY", "bolla-default-key"): "bolla",
    }


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            text TEXT NOT NULL,
            timestamp REAL NOT NULL,
            read_by TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="FamilyChat", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _authenticate_human(session_id: str | None) -> str | None:
    if not session_id or session_id not in sessions:
        return None
    session = sessions[session_id]
    if time.time() - session["created"] > 86400:
        del sessions[session_id]
        return None
    return session["user"]


def _authenticate_bot(api_key: str | None) -> str | None:
    if not api_key:
        return None
    return _get_api_keys().get(api_key)


def _get_current_user(request: Request, session_id: str | None = None) -> str:
    user = _authenticate_human(session_id)
    if user:
        last_active[user] = time.time()
        return user
    api_key = request.headers.get("X-API-Key")
    user = _authenticate_bot(api_key)
    if user:
        last_active[user] = time.time()
        return user
    raise HTTPException(status_code=401, detail="Unauthorized")


class LoginRequest(BaseModel):
    username: str
    password: str


class MessageCreate(BaseModel):
    text: str
    sender: str | None = None


@app.post("/login")
async def login(body: LoginRequest, response: Response):
    username = body.username.lower().strip()
    if username not in HUMAN_USERS:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    passwords = _get_passwords()
    if not hmac.compare_digest(_hash_password(body.password), passwords[username]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    session_id = secrets.token_hex(32)
    sessions[session_id] = {"user": username, "created": time.time()}
    last_active[username] = time.time()

    response = JSONResponse(
        content={"ok": True, "user": username, "emoji": USERS[username]["emoji"]}
    )
    response.set_cookie(
        key="session_id",
        value=session_id,
        max_age=86400,
        httponly=True,
        samesite="lax",
    )
    return response


@app.post("/logout")
async def logout(response: Response, session_id: str | None = Cookie(default=None)):
    if session_id and session_id in sessions:
        del sessions[session_id]
    response = JSONResponse(content={"ok": True})
    response.delete_cookie("session_id")
    return response


@app.get("/me")
async def me(request: Request, session_id: str | None = Cookie(default=None)):
    user = _get_current_user(request, session_id)
    return {"user": user, "emoji": USERS[user]["emoji"], "color": USERS[user]["color"]}


@app.post("/api/messages")
async def send_message(
    body: MessageCreate,
    request: Request,
    session_id: str | None = Cookie(default=None),
):
    user = _get_current_user(request, session_id)

    if body.sender and body.sender.lower() != user:
        raise HTTPException(status_code=403, detail="Cannot send as another user")

    sender = user
    text = body.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Message text cannot be empty")

    now = time.time()
    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO messages (sender, text, timestamp, read_by) VALUES (?, ?, ?, ?)",
        (sender, text, now, sender),
    )
    msg_id = cursor.lastrowid
    conn.commit()
    conn.close()

    msg = {
        "id": msg_id,
        "sender": sender,
        "text": text,
        "timestamp": now,
        "read_by": sender,
    }

    # Broadcast to all WebSocket clients
    dead = []
    for ws in ws_clients:
        try:
            await ws.send_text(json.dumps({"type": "message", **msg}))
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_clients.remove(ws)

    return msg


@app.get("/api/messages")
async def get_messages(
    request: Request,
    since: float = 0,
    limit: int = 50,
    session_id: str | None = Cookie(default=None),
):
    user = _get_current_user(request, session_id)

    conn = get_db()
    rows = conn.execute(
        "SELECT id, sender, text, timestamp, read_by FROM messages WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
        (since, limit),
    ).fetchall()
    conn.close()

    messages = [
        {
            "id": r["id"],
            "sender": r["sender"],
            "text": r["text"],
            "timestamp": r["timestamp"],
            "read_by": r["read_by"],
        }
        for r in reversed(rows)
    ]
    return {"messages": messages}


@app.get("/api/users")
async def get_users(
    request: Request, session_id: str | None = Cookie(default=None)
):
    _get_current_user(request, session_id)
    now = time.time()
    return {
        "users": [
            {
                "name": name,
                "emoji": info["emoji"],
                "color": info["color"],
                "online": (now - last_active.get(name, 0)) < 300,
            }
            for name, info in USERS.items()
        ]
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    api_key = websocket.headers.get("X-API-Key") or websocket.query_params.get("api_key")
    user = _authenticate_bot(api_key)
    if not user:
        await websocket.close(code=4001)
        return
    await websocket.accept()
    ws_clients.append(websocket)
    last_active[user] = time.time()
    try:
        while True:
            await websocket.receive_text()  # keep alive / ping
            last_active[user] = time.time()
    except WebSocketDisconnect:
        if websocket in ws_clients:
            ws_clients.remove(websocket)


app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


@app.get("/")
async def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")
