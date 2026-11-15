import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router
from capture import sniffer
from storage.database import initialize_database

@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    capture_enabled = os.getenv("CYBER_TREK_CAPTURE", "true").strip().lower() not in {"0", "false", "no", "off"}
    if capture_enabled:
        threading.Thread(target=sniffer.start_capture, name="cyber-trek-capture", daemon=True).start()
    yield

app = FastAPI(
    title="Cyber Trek API",
    description="Live network traffic monitoring and heuristic threat detection.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(router)
