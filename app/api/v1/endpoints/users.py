from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.db import get_db
from app.models.user import User
from app.schemas.user import UserOut, UserUpdate, UserDelete, UserCreate
from app.core.security import get_password_hash, create_verification_token
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from app.api.deps import get_current_user
from app.tasks.email import send_test_email, send_verification_email
from app.core.limiter import limiter
from app.schemas.user import UserOut, UserUpdate
from app.api.deps import get_current_user
from app.core.security import verify_password
router = APIRouter()

@router.post("/", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")
def register_user(
    request: Request, 
    user_in: UserCreate, 
    db: Session = Depends(get_db)
):
    """
    Register a new user in the system.
    Rate Limited: 5 per hour.
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


@router.patch("/me", response_model=UserOut)
def update_user_me(
    user_in: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Update current user profile.
    Only provided fields will be updated.
    """
    # Check if email is being updated and if it's already taken
    if user_in.email and user_in.email != current_user.email:
        existing_user = db.query(User).filter(User.email == user_in.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )

    # Update user attributes dynamically
    user_data = user_in.model_dump(exclude_unset=True)
    for field, value in user_data.items():
        setattr(current_user, field, value)

    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    
    return current_user

@router.delete("/me", status_code=status.HTTP_200_OK)
def delete_user_me(
    body: UserDelete,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Permanently delete the current user's account.
    
    This is a hard delete operation. It requires password verification
    to ensure the request is legitimate.
    """
    
    # Verify the provided password against the stored hash
    if not verify_password(body.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password"
        )

    # Perform the hard delete
    try:
        db.delete(current_user)
        db.commit()
    except Exception as e:
        db.rollback()
        # Log the error here if you have a logger configured
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account"
        )
    
    return {"message": "Account deleted successfully"}