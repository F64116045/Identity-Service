import secrets
import hashlib
import base64
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
from app.core.limiter import limiter

router = APIRouter()

# Connect to Redis (used for token blacklisting on logout)
redis_client = redis.Redis(host=settings.REDIS_HOST, port=6379, db=0, decode_responses=True)

@router.post("/login")
@limiter.limit("5/minute")
def login_access_token(
    request: Request,
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
@limiter.limit("3/minute")
def recover_password(
    request: Request, # Required for limiter
    email: str, 
    db: Session = Depends(get_db)
):
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




def generate_pkce_pair():
    """
    Generate a PKCE code_verifier and code_challenge.
    Returns: (code_verifier, code_challenge)
    """
    code_verifier = secrets.token_urlsafe(64)
    
    hashed = hashlib.sha256(code_verifier.encode("ascii")).digest()
    
    code_challenge = base64.urlsafe_b64encode(hashed).decode("ascii").rstrip("=")
    
    return code_verifier, code_challenge


@router.get("/login/google")
def login_google():
    """
    Generate the Google Login URL and redirect the user to Google.
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")

    # Generate CSRF State
    state = secrets.token_urlsafe(32)

    # Generate PKCE Verifier and Challenge
    code_verifier, code_challenge = generate_pkce_pair()

    google_auth_url = (
        "https://accounts.google.com/o/oauth2/auth"
        "?response_type=code"
        f"&client_id={settings.GOOGLE_CLIENT_ID}"
        f"&redirect_uri={settings.GOOGLE_REDIRECT_URI}"
        "&scope=openid%20email%20profile"
        "&access_type=offline"
        f"&state={state}"
        f"&code_challenge={code_challenge}"
        "&code_challenge_method=S256"
    )
    response = RedirectResponse(google_auth_url)
     # Determine if we are in production to set 'secure' flag
    # Assuming you might add an ENVIRONMENT variable later, defaulting to False for local dev
    is_production = False 

    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        max_age=300,
        samesite="lax",
        secure=is_production,
    )

    response.set_cookie(
        key="oauth_verifier",
        value=code_verifier,
        httponly=True,
        max_age=300,
        samesite="lax",
        secure=is_production,
    )
    
    return response


@router.get("/google/callback")
async def google_callback(
    request: Request,
    response: Response, 
    db: Session = Depends(get_db)
):
    """
    Handle Google Callback with State validation and PKCE exchange.
    """
    # Extract parameters from query string
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    if error:
        raise HTTPException(status_code=400, detail=f"Google OAuth Error: {error}")

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state parameter")

    # Retrieve State and Verifier from Cookies
    cookie_state = request.cookies.get("oauth_state")
    code_verifier = request.cookies.get("oauth_verifier")

    # A. Validate State (CSRF Protection)
    if not cookie_state or state != cookie_state:
        raise HTTPException(status_code=400, detail="Invalid state parameter (Potential CSRF attack)")
    
    # B. Ensure we have the PKCE verifier
    if not code_verifier:
        raise HTTPException(status_code=400, detail="Missing PKCE verifier")

    # Clean up cookies immediately
    response.delete_cookie("oauth_state")
    response.delete_cookie("oauth_verifier")

    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Configuration missing")

    # Exchange Code for Token (With PKCE Verifier)
    token_url = "https://oauth2.googleapis.com/token"
    payload = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
    }

    async with httpx.AsyncClient() as client:
        #Get Access Token
        token_res = await client.post(token_url, data=payload)
        
        if token_res.status_code != 200:
            # Helpful for debugging: print(token_res.text)
            raise HTTPException(status_code=400, detail="Failed to retrieve Google token")
        
        token_data = token_res.json()
        google_access_token = token_data.get("access_token")

        #  Get User Info
        user_info_res = await client.get(
            "https://www.googleapis.com/oauth2/v1/userinfo",
            headers={"Authorization": f"Bearer {google_access_token}"}
        )
        if user_info_res.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to retrieve user info")
        
        user_data = user_info_res.json()
        
    # Extract User Data
    email = user_data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email not found in Google account")


    query = select(User).where(User.email == email)
    user = db.execute(query).scalar_one_or_none()

    if not user:
        # Create new user (Auto-active)
        user = User(
            email=email,
            full_name=user_data.get("name"),
            is_active=True, 
            hashed_password=None
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Activate existing user if inactive
        if not user.is_active:
            user.is_active = True
            db.add(user)
            db.commit()

    # Issue Application Tokens
    user_id = str(user.id)
    access_token = create_access_token(data={"sub": user_id})
    refresh_token = create_refresh_token(data={"sub": user_id})

    # Redirect to Frontend
    frontend_redirect_url = f"{settings.FRONTEND_URL}/dashboard"
    is_prod = settings.ENVIRONMENT == "production"
    # We use a new RedirectResponse because we need to set the refresh cookie on it
    redirect_resp = RedirectResponse(frontend_redirect_url)
    
    # Set Access Token Cookie (Short-lived)
    redirect_resp.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=is_prod,
        samesite="lax",
        max_age=900,
    )

    # Set Refresh Token Cookie (Long-lived)
    redirect_resp.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=is_prod,
        samesite="lax",
        max_age=604800, # 7 days
    )
    
    # Ensure cleanup cookies are also cleared on this response object
    redirect_resp.delete_cookie("oauth_state")
    redirect_resp.delete_cookie("oauth_verifier")

    return redirect_resp