from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List, Union
import os


class Settings(BaseSettings):
    # Database (SQLite for local development)
    DATABASE_URL: str = "sqlite+aiosqlite:///./securesite_audit.db"
    
    # JWT
    JWT_SECRET_KEY: str = "your-super-secret-jwt-key-change-this-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Backend
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000"]
    API_V1_PREFIX: str = "/api/v1"

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["http://localhost:3000"]
    
    # Redis (optional - disabled for local development)
    REDIS_URL: str = ""
    
    # Email
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "noreply@securesite-audit.com"
    
    # Application
    APP_NAME: str = "SecureSite Audit"
    APP_URL: str = "http://localhost:3000"
    DEBUG: bool = True
    
    # Audit
    AUDIT_TIMEOUT_SECONDS: int = 120
    MAX_CONCURRENT_AUDITS: int = 5
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
