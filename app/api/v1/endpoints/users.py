from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.db import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserOut
from app.core.security import get_password_hash
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from app.api.deps import get_current_user
from app.tasks.email import send_test_email

router = APIRouter()

@router.post("/", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register_user(user_in: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user in the system.
    """
    # Check if user already exists
    query = select(User).where(User.email == user_in.email)
    existing_user = db.execute(query).scalar_one_or_none()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this email already exists in the system.",
        )


    hashed_password = get_password_hash(user_in.password)

    db_user = User(
        email=user_in.email,
        hashed_password=hashed_password,
        full_name=user_in.full_name,
        is_active=False
    )

    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        token = create_verification_token(db_user.email)
        send_verification_email.delay(db_user.email, token)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Database integrity error. Possibly duplicate data.",
        )
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed.",
        )

    return db_user


@router.get("/me", response_model=UserOut)
def read_user_me(
    current_user: User = Depends(get_current_user)
):
    """
    Get current logged in user information.
    """
    return current_user


@router.post("/test-email/{email}", status_code=202)
def trigger_test_email(
    email: str,
    current_user: User = Depends(get_current_user)
):
    """
    Trigger a background email task.
    Returns 202 Accepted immediately without waiting for the email to be sent.
    """
    # .delay() is the Celery magic that pushes the task to Redis
    send_test_email.delay(email)
    
    return {"message": "Task received. Email will be sent in the background."}