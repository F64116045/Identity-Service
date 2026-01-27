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