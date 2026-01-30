from datetime import timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.db import get_db
from app.core.config import settings
from app.core.security import create_access_token, verify_password, verify_email_token
from app.models.user import User
from app.schemas.user import Token

router = APIRouter()

@router.post("/login", response_model=Token)
def login_access_token(
    db: Session = Depends(get_db), 
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests.
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


    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return {
        "access_token": create_access_token(
            data={"sub": str(user.id)}, expires_delta=access_token_expires
        ),
        "token_type": "bearer",
    }


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