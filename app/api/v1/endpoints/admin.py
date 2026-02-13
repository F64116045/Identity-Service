from typing import List
from fastapi import APIRouter, Depends, Security, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc

from app.api import deps
from app.core.db import get_db
from app.core.security import get_password_hash
from app.core.logging import logger
from app.models.user import User
from app.schemas.user import UserOut, UserAdminUpdate, UserListResponse

router = APIRouter()

@router.get("/users", response_model=UserListResponse)
def read_users(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: User = Security(deps.get_current_user, scopes=["admin"]),
):
    """
    Retrieve all users (Admin only).
    Supports pagination via skip/limit.
    """

    count_stmt = select(func.count()).select_from(User)
    total_count = db.execute(count_stmt).scalar() or 0


    stmt = (
        select(User)
        .order_by(desc(User.created_at)) 
        .offset(skip)
        .limit(limit)
    )
    users = db.execute(stmt).scalars().all()
    
    return {
        "total": total_count,
        "items": users
    }

@router.get("/users/{user_id}", response_model=UserOut)
def read_user_by_id(
    user_id: str, 
    current_user: User = Security(deps.get_current_user, scopes=["admin"]),
    db: Session = Depends(get_db),
):
    """
    Get a specific user by ID.
    """
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user

@router.patch("/users/{user_id}", response_model=UserOut)
def update_user_by_admin(
    user_id: str,
    user_in: UserAdminUpdate,
    db: Session = Depends(get_db),
    current_user: User = Security(deps.get_current_user, scopes=["admin"]),
):
    """
    Update a user's details, including status and privileges.
    Allows Admin to:
    - Ban/Unban users (is_active)
    - Promote/Demote admins (is_superuser)
    - Reset passwords
    """
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Convert Pydantic model to dict, excluding unset fields
    update_data = user_in.model_dump(exclude_unset=True)

    # Handle password hashing if password is being reset
    if "password" in update_data and update_data["password"]:
        hashed_password = get_password_hash(update_data["password"])
        del update_data["password"]
        user.hashed_password = hashed_password

    # Update attributes
    for field, value in update_data.items():
        if hasattr(user, field):
            setattr(user, field, value)

    db.add(user)
    db.commit()
    db.refresh(user)
    
    logger.info(
        "admin.user_updated", 
        admin=current_user.email, 
        target_user=user.email, 
        changes=list(update_data.keys())
    )
    
    return user

@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user_by_admin(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Security(deps.get_current_user, scopes=["admin"]),
):
    """
    Hard delete a user from the system.
    """
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Prevent admin from deleting themselves (Safety check)
    if str(user.id) == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own admin account via this endpoint."
        )

    db.delete(user)
    db.commit()
    
    logger.info("admin.user_deleted", admin=current_user.email, target_user_id=str(user_id))
    return None # 204 No Content