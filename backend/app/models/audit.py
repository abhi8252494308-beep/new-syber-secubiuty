from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.database import Base


class Audit(Base):
    __tablename__ = "audits"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain_id = Column(String(36), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(50), default="pending")
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    overall_score = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    domain = relationship("Domain", back_populates="audits")
    results = relationship("AuditResult", back_populates="audit", cascade="all, delete-orphan")
    tls_result = relationship("TLSResult", back_populates="audit", uselist=False, cascade="all, delete-orphan")
    header_result = relationship("HeaderResult", back_populates="audit", uselist=False, cascade="all, delete-orphan")
    cookie_results = relationship("CookieResult", back_populates="audit", cascade="all, delete-orphan")
    robots_result = relationship("RobotsResult", back_populates="audit", uselist=False, cascade="all, delete-orphan")
    security_txt_result = relationship("SecurityTxtResult", back_populates="audit", uselist=False, cascade="all, delete-orphan")
    server_info_result = relationship("ServerInfoResult", back_populates="audit", uselist=False, cascade="all, delete-orphan")
    pdf_report = relationship("PDFReport", back_populates="audit", uselist=False, cascade="all, delete-orphan")


class AuditResult(Base):
    __tablename__ = "audit_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    check_category = Column(String(100), nullable=False)
    check_name = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False)
    score = Column(Integer, nullable=True)
    max_score = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)
    recommendations = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    audit = relationship("Audit", back_populates="results")


class TLSResult(Base):
    __tablename__ = "tls_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    has_https = Column(Boolean, default=False)
    tls_version = Column(String(20), nullable=True)
    cipher_suite = Column(String(255), nullable=True)
    certificate_valid = Column(Boolean, default=False)
    certificate_issuer = Column(String(500), nullable=True)
    certificate_subject = Column(String(500), nullable=True)
    certificate_not_before = Column(DateTime(timezone=True), nullable=True)
    certificate_not_after = Column(DateTime(timezone=True), nullable=True)
    certificate_days_remaining = Column(Integer, nullable=True)
    certificate_san = Column(JSON, nullable=True)
    hsts_enabled = Column(Boolean, default=False)
    hsts_max_age = Column(Integer, nullable=True)
    hsts_include_subdomains = Column(Boolean, default=False)
    hsts_preload = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    audit = relationship("Audit", back_populates="tls_result")


class HeaderResult(Base):
    __tablename__ = "header_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    content_security_policy = Column(String(1000), nullable=True)
    csp_valid = Column(Boolean, default=False)
    x_frame_options = Column(String(100), nullable=True)
    x_content_type_options = Column(String(100), nullable=True)
    x_xss_protection = Column(String(100), nullable=True)
    referrer_policy = Column(String(100), nullable=True)
    permissions_policy = Column(String(500), nullable=True)
    strict_transport_security = Column(String(200), nullable=True)
    cross_origin_opener_policy = Column(String(100), nullable=True)
    cross_origin_resource_policy = Column(String(100), nullable=True)
    cross_origin_embedder_policy = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    audit = relationship("Audit", back_populates="header_result")


class CookieResult(Base):
    __tablename__ = "cookie_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    cookie_name = Column(String(255), nullable=False)
    has_secure_flag = Column(Boolean, default=False)
    has_httponly_flag = Column(Boolean, default=False)
    has_samesite_flag = Column(Boolean, default=False)
    samesite_value = Column(String(20), nullable=True)
    path = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    audit = relationship("Audit", back_populates="cookie_results")


class RobotsResult(Base):
    __tablename__ = "robots_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    exists = Column(Boolean, default=False)
    content = Column(Text, nullable=True)
    sitemap_urls = Column(JSON, nullable=True)
    has_security_txt_reference = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    audit = relationship("Audit", back_populates="robots_result")


class SecurityTxtResult(Base):
    __tablename__ = "security_txt_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    exists = Column(Boolean, default=False)
    content = Column(Text, nullable=True)
    contact_urls = Column(JSON, nullable=True)
    expires = Column(DateTime(timezone=True), nullable=True)
    encryption_urls = Column(JSON, nullable=True)
    policy_urls = Column(JSON, nullable=True)
    acknowledged_urls = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    audit = relationship("Audit", back_populates="security_txt_result")


class ServerInfoResult(Base):
    __tablename__ = "server_info_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    server_header = Column(String(255), nullable=True)
    x_powered_by = Column(String(255), nullable=True)
    technology_stack = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    country = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    audit = relationship("Audit", back_populates="server_info_result")


class PDFReport(Base):
    __tablename__ = "pdf_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, nullable=True)
    generated_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    download_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    audit = relationship("Audit", back_populates="pdf_report")