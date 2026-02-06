from datetime import timedelta, datetime, timezone
from typing import Any
import redis
import httpx
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import select
from fastapi.responses import RedirectResponse
from app.core.db import get_db
from app.core.config import settings
from app.core.security import (
    create_access_token, 
    create_refresh_token, 
    create_verification_token,
    verify_password, 
    verify_email_token,
    verify_token_scope, # New helper for verifying password reset tokens
    decode_token,
    get_password_hash,  # Needed for hashing the new password
)
from app.models.user import User
from app.schemas.user import Token
# Make sure to implement send_password_reset_email in app/tasks/email.py
from app.tasks.email import send_password_reset_email 

router = APIRouter()

# Connect to Redis (used for token blacklisting on logout)
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
        # Calculate remaining time to live (TTL) for the token
        exp = token.get("exp")
        # Ensure exp exists
        if exp:
            now = datetime.now(timezone.utc).timestamp()
            ttl = int(exp - now)
            
            # If token is still valid, blacklist it
            if ttl > 0:
                auth_header = request.headers.get("Authorization")
                if auth_header:
                    raw_token = auth_header.split(" ")[1]
                    redis_client.setex(f"blacklist:{raw_token}", ttl, "true")

    # Clear cookie
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
        # Generate token with specific scope "password_reset"
        token = create_verification_token(email, scope="password_reset")
        
        # Trigger Celery task
        send_password_reset_email.delay(email, token)
        
    # Always return a generic message to prevent user enumeration attacks
    return {"message": "If the account exists, a password reset email has been sent."}

@router.post("/reset-password")
def reset_password(
    token: str = Body(...), 
    new_password: str = Body(...), 
    db: Session = Depends(get_db)
):
    """
    Reset password using the token received in email.
    """
    # Verify token specifically for password_reset scope
    email = verify_token_scope(token, "password_reset")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )
    
    query = select(User).where(User.email == email)
    user = db.execute(query).scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update password
    user.hashed_password = get_password_hash(new_password)
    db.add(user)
    db.commit()
    
    return {"message": "Password updated successfully. You can now log in."}

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




@router.get("/login/google")
def login_google():
    """
    Generate the Google Login URL and redirect the user to Google.
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")

    google_auth_url = (
        "https://accounts.google.com/o/oauth2/auth"
        "?response_type=code"
        f"&client_id={settings.GOOGLE_CLIENT_ID}"
        f"&redirect_uri={settings.GOOGLE_REDIRECT_URI}"
        "&scope=openid%20email%20profile"
        "&access_type=offline"
    )
    
    return RedirectResponse(google_auth_url)


@router.get("/google/callback")
async def google_callback(
    code: str, 
    response: Response, 
    db: Session = Depends(get_db)
):
    """
    Process Google Callback:
    1. Exchange code for Google Token.
    2. Get user info.
    3. Register or Login user.
    4. Issue JWT tokens.
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth configuration missing")

    # Exchange Code for Token
    token_url = "https://oauth2.googleapis.com/token"
    payload = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code": code,
    }

    async with httpx.AsyncClient() as client:
        # Get Google Access Token
        token_res = await client.post(token_url, data=payload)
        if token_res.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to retrieve Google token")
        
        token_data = token_res.json()
        google_access_token = token_data.get("access_token")

        # Get User Info
        user_info_res = await client.get(
            "https://www.googleapis.com/oauth2/v1/userinfo",
            headers={"Authorization": f"Bearer {google_access_token}"}
        )
        if user_info_res.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to retrieve user info")
        
        user_data = user_info_res.json()
        
    # Extract Data
    email = user_data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email not found in Google account")

    # Check / Create User
    query = select(User).where(User.email == email)
    user = db.execute(query).scalar_one_or_none()

    if not user:
        # New User: Create account (Active by default for social login)
        user = User(
            email=email,
            full_name=user_data.get("name"),
            is_active=True, 
            hashed_password=None # No password for Google users
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Existing User: Ensure account is active if they login via Google
        if not user.is_active:
            user.is_active = True
            db.add(user)
            db.commit()

    # Issue Our JWT Tokens
    user_id = str(user.id)
    access_token = create_access_token(data={"sub": user_id})
    refresh_token = create_refresh_token(data={"sub": user_id})

    # Set HttpOnly Cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=60 * 60 * 24 * 7,
        samesite="lax", 
        secure=False,  # Need to change in production
    )

    frontend_url = f"{settings.FRONTEND_URL}/dashboard?token={access_token}"
    return RedirectResponse(frontend_url)