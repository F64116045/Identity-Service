from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
import os

class Settings(BaseSettings):
    PROJECT_NAME: str = "Identity Service"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"

    ALGORITHM: str = "RS256"
    SIG_KEY_ID: str = "dev-key-001"
    PRIVATE_KEY_PATH: str = "certs/private.pem"
    PUBLIC_KEY_PATH: str = "certs/public.pem"
    @property
    def PRIVATE_KEY(self) -> str:
        """Read content of the private key file"""
        path = self.PRIVATE_KEY_PATH
        if not os.path.exists(path):
            raise FileNotFoundError(f"Private key not found at {path}")
        with open(path, "r") as f:
            return f.read()

    @property
    def PUBLIC_KEY(self) -> str:
        """Read content of the public key file"""
        path = self.PUBLIC_KEY_PATH
        if not os.path.exists(path):
            raise FileNotFoundError(f"Public key not found at {path}")
        with open(path, "r") as f:
            return f.read()

    POSTGRES_SERVER: str = Field(default="localhost")
    POSTGRES_USER: str = Field(default="postgres")
    POSTGRES_PASSWORD: str = Field(default="password")
    POSTGRES_DB: str = Field(default="identity_db")
    POSTGRES_PORT: int = Field(default=5432)
    REDIS_HOST: str = Field(default="localhost")
 
    SECRET_KEY: str = Field(default="super-secret-key-for-dev-only")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # SMTP / Email Settings
    SMTP_TLS: bool = True
    SMTP_PORT: int = 587
    SMTP_HOST: str | None = None
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    EMAILS_FROM_EMAIL: str | None = None
    EMAILS_FROM_NAME: str | None = Field(default=None, alias="PROJECT_NAME")

    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: str | None = None
    # Important : Need to change in production
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/google/callback"
    FRONTEND_URL: str | None = None
    BACKEND_CORS_ORIGINS: str | None = None
    ENVIRONMENT: str | None = "development"
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        case_sensitive=True
    )


settings = Settings()