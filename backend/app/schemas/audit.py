from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID


class AuditBase(BaseModel):
    domain_id: UUID


class AuditCreate(AuditBase):
    pass


class AuditResultResponse(BaseModel):
    id: UUID
    audit_id: UUID
    check_category: str
    check_name: str
    status: str
    score: Optional[int] = None
    max_score: Optional[int] = None
    details: Optional[Dict[str, Any]] = None
    recommendations: Optional[List[str]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class TLSResultResponse(BaseModel):
    has_https: bool
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_valid: bool
    certificate_issuer: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_not_before: Optional[datetime] = None
    certificate_not_after: Optional[datetime] = None
    certificate_days_remaining: Optional[int] = None
    hsts_enabled: bool
    hsts_max_age: Optional[int] = None
    hsts_include_subdomains: bool
    hsts_preload: bool

    class Config:
        from_attributes = True


class HeaderResultResponse(BaseModel):
    content_security_policy: Optional[str] = None
    csp_valid: bool
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    x_xss_protection: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    strict_transport_security: Optional[str] = None
    cross_origin_opener_policy: Optional[str] = None
    cross_origin_resource_policy: Optional[str] = None
    cross_origin_embedder_policy: Optional[str] = None

    class Config:
        from_attributes = True


class CookieResultResponse(BaseModel):
    cookie_name: str
    has_secure_flag: bool
    has_httponly_flag: bool
    has_samesite_flag: bool
    samesite_value: Optional[str] = None

    class Config:
        from_attributes = True


class RobotsResultResponse(BaseModel):
    exists: bool
    content: Optional[str] = None
    sitemap_urls: Optional[List[str]] = None
    has_security_txt_reference: bool

    class Config:
        from_attributes = True


class SecurityTxtResultResponse(BaseModel):
    exists: bool
    content: Optional[str] = None
    contact_urls: Optional[List[str]] = None
    expires: Optional[datetime] = None
    encryption_urls: Optional[List[str]] = None
    policy_urls: Optional[List[str]] = None

    class Config:
        from_attributes = True


class ServerInfoResultResponse(BaseModel):
    server_header: Optional[str] = None
    x_powered_by: Optional[str] = None
    technology_stack: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    country: Optional[str] = None
    isp: Optional[str] = None

    class Config:
        from_attributes = True


class AuditResponse(BaseModel):
    id: UUID
    domain_id: UUID
    user_id: Optional[UUID] = None
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    overall_score: Optional[int] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    results: List[AuditResultResponse] = []
    tls_result: Optional[TLSResultResponse] = None
    header_result: Optional[HeaderResultResponse] = None
    cookie_results: List[CookieResultResponse] = []
    robots_result: Optional[RobotsResultResponse] = None
    security_txt_result: Optional[SecurityTxtResultResponse] = None
    server_info_result: Optional[ServerInfoResultResponse] = None

    class Config:
        from_attributes = True


class AuditSummary(BaseModel):
    id: UUID
    domain_id: UUID
    domain_name: str
    status: str
    overall_score: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True