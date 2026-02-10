from pydantic import BaseModel, EmailStr

class GoogleUserInfo(BaseModel):
    """Schema for user info returned by Google OAuth2"""
    id: str
    email: EmailStr
    verified_email: bool
    name: str
    picture: str | None = None