from pydantic import BaseModel, EmailStr, ConfigDict


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None


class UserOut(BaseModel):
    email: EmailStr
    full_name: str | None = None
    is_active: bool


    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    """Schema for the token response"""
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """Schema for data stored inside the JWT (Payload)"""
    user_id: str | None = None