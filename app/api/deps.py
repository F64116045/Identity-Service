import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db 
from app.core.security import ALGORITHM
from app.models.user import User
from app.schemas.user import TokenData

# OAuth2 scheme: Points to the login endpoint to fetch the token
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login"
)

def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """
    1. Extracts the token from the request header.
    2. Decodes the JWT to find the user ID (subject).
    3. Validates user existence and status.
    """
    try:
        # Decode JWT token using the system's secret key
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
        token_data = TokenData(user_id=user_id)
    except (jwt.PyJWTError, ValidationError):
        # Handle cases where token is expired, tampered, or invalid format
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    
    # Fetch user from database using the ID from token payload
    user = db.get(User, token_data.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="User not found"
        )
    
    # Safety check: Ensure the account hasn't been deactivated
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Inactive user"
        )
        
    return user