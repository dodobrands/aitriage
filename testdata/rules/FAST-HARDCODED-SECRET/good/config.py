import secrets

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SECRET_KEY: str = secrets.token_urlsafe(32)
    API_KEY_HEADER: str = "X-API-Key"
    # SECRET_KEY: str = "do-not-hardcode-me"
    jwt_secret: str
