# config.py
from __future__ import annotations
import os
from dataclasses import dataclass


def _env(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return default if v is None else v


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or not str(v).strip():
        return default
    try:
        return int(v)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # App
    APP_NAME: str = _env("APP_NAME", "Tracklet")
    SECRET_KEY: str = _env("SECRET_KEY", "dev-only-change-me-for-traclet")

    # Storage (Railway Volume)
    # Recommended: DB_PATH=/data/tasker.sqlite3
    DB_PATH: str = _env("DB_PATH", "data/tracklet.sqlite3")

    # Optional: uploads for later (attachments)
    # Recommended: UPLOAD_DIR=/data/uploads
    UPLOAD_DIR: str = _env("UPLOAD_DIR", "data/uploads")

    # Mail 
     # ---- Mail (dynamic) ----
    @property
    def MAIL_PROVIDER(self) -> str:
        return _env("MAIL_PROVIDER", "smtp")

    @property
    def RESEND_API_KEY(self) -> str:
        return _env("RESEND_API_KEY", "")

    @property
    def SMTP_FROM(self) -> str:
        return _env("SMTP_FROM", "no-reply@tracklet.app")

    @property
    def SMTP_HOST(self) -> str:
        return _env("SMTP_HOST", "")

    @property
    def SMTP_PORT(self) -> int:
        return _env_int("SMTP_PORT", 587)

    @property
    def SMTP_USER(self) -> str:
        return _env("SMTP_USER", "")

    @property
    def SMTP_PASS(self) -> str:
        return _env("SMTP_PASS", "")
    
    """ MAIL_PROVIDER: str = _env("MAIL_PROVIDER", "smtp")
    # Resend
    RESEND_API_KEY: str = _env("RESEND_API_KEY", "")    
    SMTP_HOST: str = _env("SMTP_HOST", "")
    SMTP_PORT: int = _env_int("SMTP_PORT", "")
    SMTP_USER: str = _env("SMTP_USER", "")
    #SMTP_PASS: str = _env("SMTP_PASS", "ycbn ddss uepq xtyb")
    SMTP_PASS: str = _env("SMTP_PASS", "")
    #SMTP_FROM: str = _env("SMTP_FROM", "Avivimmantis@gmail.com")  # if empty, fallback to SMTP_USER
    SMTP_FROM: str = _env("SMTP_FROM", "no-reply@tracklet.app")  # if empty, fallback to SMTP_USER """

    # Bootstrap admin (only used if DB is empty)
    BOOTSTRAP_ADMIN_EMAIL: str = _env("BOOTSTRAP_ADMIN_EMAIL", "admin@local")
    BOOTSTRAP_ADMIN_PASSWORD: str = _env("BOOTSTRAP_ADMIN_PASSWORD", "admin1234")
    BOOTSTRAP_ADMIN_NAME: str = _env("BOOTSTRAP_ADMIN_NAME", "Admin")


settings = Settings()
