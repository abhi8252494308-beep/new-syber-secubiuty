from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from uuid import UUID


class DomainBase(BaseModel):
    domain_name: str = Field(..., min_length=3, max_length=255)


class DomainCreate(DomainBase):
    verification_method: str = "dns"


class DomainResponse(DomainBase):
    id: UUID
    is_verified: bool
    verification_method: str
    verification_token: Optional[str] = None
    is_active: bool
    last_audit_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DomainVerification(BaseModel):
    domain_id: UUID
    verification_token: str
    verification_method: str = "dns"
    message: str


class DomainVerificationResponse(BaseModel):
    success: bool
    message: str