from pydantic import BaseModel, EmailStr, ConfigDict, Field
from typing import List
import uuid

class UserBase(BaseModel):
    email: EmailStr
    full_name: str | None = None
    is_active: bool = True

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

class UserUpdate(BaseModel):
    """
    Payload for PATCH /users/me.
    All fields are optional to allow partial updates.
    """
    email: EmailStr | None = None
    full_name: str | None = None
    password: str | None = Field(None, min_length=8)

class UserPasswordUpdate(BaseModel):
    """
    Payload for POST /auth/change-password.
    Requires strict validation for the new password.
    """
    current_password: str
    new_password: str = Field(..., min_length=8)

class UserOut(UserBase):
    id: uuid.UUID
    
    model_config = ConfigDict(from_attributes=True)

class UserDelete(BaseModel):
    """
    Schema for account deletion.
    Requires password confirmation to prevent accidental or malicious deletions.
    """
    password: str = Field(..., description="Current password for verification")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: str | None = None
    scopes: List[str] = []


class UserAdminUpdate(BaseModel):
    """
    Schema for Admin-only updates.
    Allows modifying sensitive fields like account status and role.
    """
    email: EmailStr | None = None
    full_name: str | None = None
    is_active: bool | None = None
    is_superuser: bool | None = None
    password: str | None = Field(None, min_length=8, description="Admin reset password")


class UserListResponse(BaseModel):
    """
    Pagination response wrapper.
    """
    total: int
    items: List[UserOut]