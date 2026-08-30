from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.database import Base


class Domain(Base):
    __tablename__ = "domains"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain_name = Column(String(255), nullable=False, index=True, unique=True)
    is_verified = Column(Boolean, default=False)
    verification_method = Column(String(50), default="dns")
    verification_token = Column(String(255), nullable=False)
    verification_token_expires = Column(DateTime(timezone=True), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    last_audit_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    audits = relationship("Audit", back_populates="domain", cascade="all, delete-orphan")