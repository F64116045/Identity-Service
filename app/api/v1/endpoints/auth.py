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
from app.tasks.email import send_password_reset_email 
from app.core.limiter import limiter
from app.core.logging import logger
from app.schemas.auth import GoogleUserInfo
from app.core.metrics import AUTH_EVENTS

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

    AUTH_EVENTS.labels(method="password_login", status="success").inc()
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
        AUTH_EVENTS.labels(method="refresh_token", status="missing").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Refresh token missing"
        )
    
    # Verify the token
    payload = decode_token(token)
    if not payload or payload.get("type") != "refresh":
        AUTH_EVENTS.labels(method="refresh_token", status="invalid").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid or expired refresh token"
        )
    
    # Issue new access token
    new_access_token = create_access_token(data={"sub": payload.get("sub")})
    

    AUTH_EVENTS.labels(method="refresh_token", status="success").inc()
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
    AUTH_EVENTS.labels(method="logout", status="success").inc()
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
    db: Session = Depends(get_db)
):
    """
    Handle Google OAuth2 Callback with structured logging and type-safe data handling.
    """
    # 1. Extract and validate basic query parameters
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    if error:
        AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
        logger.error("google_oauth_callback_error", error=error)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Google Error: {error}")

    if not code or not state:
        AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
        logger.warning("google_oauth_missing_params")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or state")

    # 2. CSRF & PKCE Validation
    cookie_state = request.cookies.get("oauth_state")
    code_verifier = request.cookies.get("oauth_verifier")

    if not cookie_state or state != cookie_state:
        AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
        logger.error("google_oauth_csrf_detected", state=state, cookie_state=cookie_state)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF validation failed")

    if not code_verifier:
        AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
        logger.error("google_oauth_missing_verifier")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="PKCE verifier not found")

    # 3. Exchange Code for Access Token
    logger.info("google_oauth_exchanging_code")
    async with httpx.AsyncClient() as client:
        token_url = "https://oauth2.googleapis.com/token"
        token_payload = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
        }
        
        token_res = await client.post(token_url, data=token_payload)
        if token_res.status_code != 200:
            AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
            logger.error("google_token_exchange_failed", response=token_res.text)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to get tokens")

        google_tokens = token_res.json()
        access_token_google = google_tokens.get("access_token")

        # 4. Fetch User Info from Google
        user_info_res = await client.get(
            "https://www.googleapis.com/oauth2/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token_google}"}
        )
        if user_info_res.status_code != 200:
            AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
            logger.error("google_user_info_fetch_failed", response=user_info_res.text)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to get user info")

        # Parse with Pydantic for type safety
        try:
            google_user = GoogleUserInfo(**user_info_res.json())
        except Exception as e:
            AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
            logger.error("google_user_data_parsing_failed", error=str(e))
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid user data format")

    # 5. Database Logic: Account Upsert/Linking
    query = select(User).where(User.email == google_user.email)
    user = db.execute(query).scalar_one_or_none()

    if not user:
        logger.info("google_oauth_creating_new_user", email=google_user.email)
        user = User(
            email=google_user.email,
            full_name=google_user.name,
            is_active=True,  # OAuth users are pre-verified
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
    except Exception as e:
        db.rollback()
        logger.error("google_oauth_db_commit_failed", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")

    # 6. Build Response and Set Application Tokens
    response = RedirectResponse(url=f"{settings.FRONTEND_URL}/dashboard")
    
    # Issue JWTs
    user_id = str(user.id)
    access_token = create_access_token(data={"sub": user_id})
    refresh_token = create_refresh_token(data={"sub": user_id})

    # Cookie configuration
    cookie_params = {
        "httponly": True,
        "secure": settings.ENVIRONMENT == "production",
        "samesite": "lax",
    }

    response.set_cookie(key="access_token", value=access_token, max_age=900, **cookie_params)
    response.set_cookie(key="refresh_token", value=refresh_token, max_age=604800, **cookie_params)

    # Cleanup OAuth cookies on the SAME response object
    response.delete_cookie("oauth_state")
    response.delete_cookie("oauth_verifier")
    
    AUTH_EVENTS.labels(method="google_login", status="success").inc()

    logger.info("google_oauth_success", user_id=user_id)
    return response