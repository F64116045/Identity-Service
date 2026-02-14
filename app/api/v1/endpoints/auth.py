from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Body
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.db import get_db
from app.core.config import settings
from app.core.security import (
    create_access_token, 
    create_refresh_token, 
    create_verification_token, 
    verify_password,
    verify_token_purpose, 
    decode_token,
    get_password_hash,
    get_user_scope_string
)
from app.models.user import User
from app.tasks.email import send_password_reset_email 
from app.core.limiter import limiter
from app.core.logging import logger
from app.core.metrics import AUTH_EVENTS
from app.schemas.user import UserPasswordUpdate
from app.api.deps import get_current_user

from app.services.auth_service import AuthService
from app.services.google_service import GoogleService

router = APIRouter()

@router.post("/login")
@limiter.limit("5/minute")
def login_access_token(
    request: Request,
    response: Response,
    db: Session = Depends(get_db), 
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """
    OAuth2 compatible token login (Double Token).
    """
    # Authenticate via Service
    user = AuthService.authenticate_user(db, form_data.username, form_data.password)

    # Generate Tokens
    user_id = str(user.id)
    scopes = get_user_scope_string(user.is_superuser)
    access_token = create_access_token(data={"sub": user_id, "scopes": scopes})
    refresh_token = create_refresh_token(data={"sub": user_id, "scopes": scopes})

    # Set Cookie & Return
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=60 * 60 * 24 * 7, 
        samesite="lax",
        secure=settings.ENVIRONMENT == "production",
    )

    AUTH_EVENTS.labels(method="password_login", status="success").inc()
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/refresh")
def refresh_token(
    request: Request, 
    db: Session = Depends(get_db)
):
    """
    Exchange Refresh Token for new Access Token.
    """
    token = request.cookies.get("refresh_token")
    if not token:
        AUTH_EVENTS.labels(method="refresh_token", status="missing").inc()
        raise HTTPException(status_code=401, detail="Refresh token missing")
    
    # Delegate logic to Service
    new_access_token = AuthService.process_refresh_token(db, token)

    AUTH_EVENTS.labels(method="refresh_token", status="success").inc()
    return {"access_token": new_access_token, "token_type": "bearer"}

@router.post("/logout")
def logout(request: Request, response: Response, token: dict = Depends(decode_token)):
    """
    Logout: Clear cookie and blacklist access token.
    """
    # Delegate blacklist logic to Service
    AuthService.logout_user(request, token)

    AUTH_EVENTS.labels(method="logout", status="success").inc()
    response.delete_cookie("refresh_token")
    return {"message": "Successfully logged out"}

@router.get("/login/google")
def login_google():
    """
    Redirect to Google Login.
    """
    # Delegate URL generation to Service
    auth_url, state, code_verifier = GoogleService.generate_login_url()
    
    response = RedirectResponse(auth_url)
    is_prod = settings.ENVIRONMENT == "production"

    # Set Auth cookies
    response.set_cookie(key="oauth_state", value=state, httponly=True, max_age=300, samesite="lax", secure=is_prod)
    response.set_cookie(key="oauth_verifier", value=code_verifier, httponly=True, max_age=300, samesite="lax", secure=is_prod)
    
    return response

@router.get("/google/callback")
async def google_callback(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Handle Google Callback.
    """
    # Validation & Exchange via Google Service
    google_user = await GoogleService.get_user_from_callback(request)

    # Database Sync via Auth Service
    user = AuthService.get_or_create_google_user(db, google_user)

    # Issue Tokens
    user_id = str(user.id)
    scopes = get_user_scope_string(user.is_superuser)
    access_token = create_access_token(data={"sub": user_id, "scopes": scopes})
    refresh_token = create_refresh_token(data={"sub": user_id, "scopes": scopes})

    # Response & Cleanup
    response = RedirectResponse(url=f"{settings.FRONTEND_URL}/dashboard")
    is_prod = settings.ENVIRONMENT == "production"
    cookie_params = {"httponly": True, "secure": is_prod, "samesite": "lax"}

    response.set_cookie(key="access_token", value=access_token, max_age=900, **cookie_params)
    response.set_cookie(key="refresh_token", value=refresh_token, max_age=604800, **cookie_params)
    
    response.delete_cookie("oauth_state")
    response.delete_cookie("oauth_verifier")
    
    AUTH_EVENTS.labels(method="google_login", status="success").inc()
    logger.info("google_oauth_success", user_id=user_id)
    return response

# --- Password Recovery Endpoints ---

@router.post("/password-recovery/{email}")
@limiter.limit("3/minute")
def recover_password(
    request: Request,
    email: str, 
    db: Session = Depends(get_db)
):
    query = select(User).where(User.email == email)
    user = db.execute(query).scalar_one_or_none()
    
    if user:
        # Use 'purpose' instead of 'scope'
        token = create_verification_token(email, purpose="password_reset")
        send_password_reset_email.delay(email, token)
        
    return {"message": "If the account exists, a password reset email has been sent."}

@router.post("/reset-password")
def reset_password(
    token: str = Body(...), 
    new_password: str = Body(...), 
    db: Session = Depends(get_db)
):
    # Verify token purpose
    email = verify_token_purpose(token, "password_reset")
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    query = select(User).where(User.email == email)
    user = db.execute(query).scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.hashed_password = get_password_hash(new_password)
    db.add(user)
    db.commit()
    return {"message": "Password updated successfully."}

@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    email = verify_token_purpose(token, "email_verification")
    if not email:
        raise HTTPException(status_code=400, detail="Invalid verification token")
    
    query = select(User).where(User.email == email)
    user = db.execute(query).scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.is_active:
        user.is_active = True
        db.add(user)
        db.commit()
        return {"message": "Account activated successfully!"}
        
    return {"message": "Email already verified."}

@router.post("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    body: UserPasswordUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")

    if body.current_password == body.new_password:
        raise HTTPException(status_code=400, detail="New password cannot be same as old")

    current_user.hashed_password = get_password_hash(body.new_password)
    db.add(current_user)
    db.commit()
    return {"message": "Password updated successfully"}