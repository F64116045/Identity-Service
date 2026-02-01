from datetime import timedelta, datetime, timezone
from typing import Any
import redis
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.db import get_db
from app.core.config import settings
from app.core.security import (
    create_access_token, 
    create_refresh_token, 
    create_verification_token,
    verify_password, 
    verify_email_token,
    decode_token,
)
from app.models.user import User
from app.schemas.user import Token

router = APIRouter()

# Connect to Redis (used for token blacklisting on logout)
# decode_responses=True ensures we get strings back from Redis instead of bytes
redis_client = redis.Redis(host=settings.REDIS_HOST, port=6379, db=0, decode_responses=True)

@router.post("/login")
def login_access_token(
    response: Response,
    db: Session = Depends(get_db), 
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """
    OAuth2 compatible token login. 
    Implements Double Token Mechanism:
    1. Returns a short-lived Access Token (JSON) for API calls.
    2. Sets a long-lived Refresh Token (HttpOnly Cookie) for session renewal.
    """
    query = select(User).where(User.email == form_data.username)
    user = db.execute(query).scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Account not verified. Please check your email."
        )


    user_id = str(user.id)
    access_token = create_access_token(data={"sub": user_id})
    refresh_token = create_refresh_token(data={"sub": user_id})

    # Set HttpOnly Cookie for Refresh Token (Security Best Practice)
    # This prevents JavaScript from accessing the long-lived token (mitigates XSS)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=60 * 60 * 24 * 7,
        samesite="lax",
        secure=False,  # Set to True in production (HTTPS)
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }

@router.post("/refresh")
def refresh_token(request: Request):
    """
    Exchange a valid Refresh Token (from Cookie) for a new Access Token.
    """
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Refresh token missing"
        )
    
    # Verify the token
    payload = decode_token(token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid or expired refresh token"
        )
    
    # Issue new access token
    new_access_token = create_access_token(data={"sub": payload.get("sub")})
    
    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }

@router.post("/logout")
def logout(request: Request, response: Response, token: dict = Depends(decode_token)):
    """
    Logout user:
    1. Clear the Refresh Token cookie.
    2. Add the current Access Token to Redis Blacklist until it expires.
    """
    if token:
        exp = token.get("exp")
        if exp is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token missing expiration"
            )
        now = datetime.now(timezone.utc).timestamp()
        ttl = int(exp - now)
        
        # If token is still valid, blacklist it
        if ttl > 0:
            # Extract the raw token string from the Authorization header
            auth_header = request.headers.get("Authorization")
            if auth_header:
                raw_token = auth_header.split(" ")[1]
                redis_client.setex(f"blacklist:{raw_token}", ttl, "true")


    response.delete_cookie("refresh_token")
    return {"message": "Successfully logged out"}

@router.post("/password-recovery/{email}")
def recover_password(email: str, db: Session = Depends(get_db)):
    """
    Trigger password recovery process.
    Sends an email with a password reset token (valid for 24h).
    """
    query = select(User).where(User.email == email)
    user = db.execute(query).scalar_one_or_none()
    
    if user:
        token = create_verification_token(email, scope="password_reset")
        
        # TODO: Trigger Celery task here
        # send_password_reset_email.delay(email, token)
        

    return {"message": "If the account exists, a password reset email has been sent."}

@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    """
    Endpoint to verify email token and activate user account.
    """
    email = verify_email_token(token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )
    
    query = select(User).where(User.email == email)
    user = db.execute(query).scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="User not found"
        )
    
    if user.is_active:
        return {"message": "Email already verified. You can log in."}
    
    # Activate the account
    user.is_active = True
    db.add(user)
    db.commit()
    
    return {"message": "Account activated successfully! You can now log in."}