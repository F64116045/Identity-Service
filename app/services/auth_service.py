import redis
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select
from fastapi import HTTPException, status, Request, Response

from app.core.config import settings
from app.core.security import (
    verify_password, get_password_hash, create_access_token, 
    create_refresh_token, decode_token, get_user_scope_string
)
from app.core.logging import logger
from app.core.metrics import AUTH_EVENTS
from app.models.user import User
from app.schemas.auth import GoogleUserInfo
import uuid

# Redis Connection (Singleton logic usually managed by dependency injection, keeping simple here)
redis_client = redis.Redis(host=settings.REDIS_HOST, port=6379, db=0, decode_responses=True)

class AuthService:
    @staticmethod
    def authenticate_user(db: Session, email: str, password: str) -> User:
        """Verify user credentials and status."""
        query = select(User).where(User.email == email)
        user = db.execute(query).scalar_one_or_none()

        if not user or not verify_password(password, user.hashed_password):
            AUTH_EVENTS.labels(method="password_login", status="failure").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not user.is_active:
            AUTH_EVENTS.labels(method="password_login", status="inactive").inc()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Account not verified. Please check your email."
            )
        
        return user

    @staticmethod
    def get_or_create_google_user(db: Session, google_user: GoogleUserInfo) -> User:
        """Find existing user by email or create a new one."""
        query = select(User).where(User.email == google_user.email)
        user = db.execute(query).scalar_one_or_none()

        if not user:
            logger.info("google_oauth_creating_new_user", email=google_user.email)
            user = User(
                email=google_user.email,
                full_name=google_user.name,
                is_active=True,
                hashed_password=None
            )
            db.add(user)
        else:
            logger.info("google_oauth_login_existing_user", email=google_user.email)
            if not user.is_active:
                user.is_active = True
                db.add(user)
        
        try:
            db.commit()
            db.refresh(user)
            return user
        except Exception as e:
            db.rollback()
            logger.error("google_oauth_db_commit_failed", error=str(e))
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")

    @staticmethod
    def process_refresh_token(db: Session, token: str):
        """Validate refresh token and issue new access token."""
        payload = decode_token(token)
        if not payload or payload.get("type") != "refresh":
            AUTH_EVENTS.labels(method="refresh_token", status="invalid").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid or expired refresh token"
            )
        
        user_id_str = payload.get("sub")
        #CRITICAL FIX: SQLAlchemy + SQLite requires explicit UUID objects
        try:
            user_uuid = uuid.UUID(user_id_str)
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token subject format"
            )
        query = select(User).where(User.id == user_uuid)
        user = db.execute(query).scalar_one_or_none()
        
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer active")
        
        scopes = get_user_scope_string(user.is_superuser)
        new_access_token = create_access_token(
            data={"sub": str(user_uuid), "scopes": scopes} 
        )
        
        return new_access_token

    @staticmethod
    def logout_user(request: Request, token: dict):
        """Blacklist current access token."""
        if token:
            exp = token.get("exp")
            if exp:
                now = datetime.now(timezone.utc).timestamp()
                ttl = int(exp - now)
                if ttl > 0:
                    auth_header = request.headers.get("Authorization")
                    if auth_header:
                        raw_token = auth_header.split(" ")[1]
                        redis_client.setex(f"blacklist:{raw_token}", ttl, "true")