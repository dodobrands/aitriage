import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite://")
    # ruleid: FAST-HARDCODED-SECRET
    SECRET_KEY: str = "not-a-real-signing-__JOIN__key-0123456789"
