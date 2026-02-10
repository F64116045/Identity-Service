import jwt
import redis
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.config import settings
from app.core.db import get_db
from app.core.logging import logger
from app.models.user import User
from app.schemas.user import TokenData


redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=6379,
    db=0,
    decode_responses=True
)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login"
)

def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """
    Validate the JWT token and retrieve the current user.
    Uses RS256 Public Key verification and structlog for observability.
    """
    
    # Redis Blacklist Check
    if redis_client.exists(f"blacklist:{token}"):
        logger.warning("auth.token_revoked", token_preview=token[:10] + "...")
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # JWT (Verify & Decode)
    try:
        payload = jwt.decode(
            token,
            settings.PUBLIC_KEY,
            algorithms=[settings.ALGORITHM]
        )
        
        token_sub: str | None = payload.get("sub")
        
        if token_sub is None:
            logger.warning("auth.missing_sub_claim", token_preview=token[:10] + "...")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        token_data = TokenData(user_id=token_sub)

    except (jwt.PyJWTError, ValidationError) as e:
        logger.warning("auth.validation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


    stmt = select(User).where(User.email == token_data.user_id)
    user = db.execute(stmt).scalars().first()

    if not user:
        logger.warning("auth.user_not_found", email=token_data.user_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not user.is_active:
        logger.warning("auth.inactive_user_login_attempt", email=user.email)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )

    return user