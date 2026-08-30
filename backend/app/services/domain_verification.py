import secrets
import dns.resolver
from datetime import datetime, timedelta
from typing import Optional, Tuple, Any, Union
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status

from app.config import settings
from app.models.domain import Domain


class DomainVerificationService:
    @staticmethod
    def generate_verification_token() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    async def create_domain(
        db: AsyncSession, domain_name: str, verification_method: str = "dns"
    ) -> Domain:
        # Normalize domain name
        domain_name = domain_name.lower().strip()
        if domain_name.startswith("http://"):
            domain_name = domain_name[7:]
        if domain_name.startswith("https://"):
            domain_name = domain_name[8:]
        if domain_name.startswith("www."):
            domain_name = domain_name[4:]
        domain_name = domain_name.rstrip("/")

        # Check if domain already exists
        result = await db.execute(
            select(Domain).where(
                Domain.domain_name == domain_name,
            )
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Domain already added",
            )

        verification_token = DomainVerificationService.generate_verification_token()

        domain = Domain(
            domain_name=domain_name,
            verification_method=verification_method,
            verification_token=verification_token,
            verification_token_expires=datetime.utcnow() + timedelta(hours=72),
        )
        db.add(domain)
        await db.commit()
        await db.refresh(domain)
        return domain

    @staticmethod
    async def verify_domain(db: AsyncSession, domain_id: UUID) -> Tuple[bool, str]:
        result = await db.execute(
            select(Domain).where(Domain.id == str(domain_id))
        )
        domain = result.scalar_one_or_none()
        if not domain:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Domain not found",
            )

        if domain.is_verified:
            return True, "Domain is already verified"

        if domain.verification_token_expires and domain.verification_token_expires < datetime.utcnow():
            return False, "Verification token has expired. Please request a new verification."

        # Verify based on method
        if domain.verification_method == "dns":
            verified = await DomainVerificationService._verify_dns(domain.domain_name, domain.verification_token)
        elif domain.verification_method == "file":
            verified = await DomainVerificationService._verify_file(domain.domain_name, domain.verification_token)
        elif domain.verification_method == "meta":
            verified = await DomainVerificationService._verify_meta(domain.domain_name, domain.verification_token)
        else:
            return False, f"Unknown verification method: {domain.verification_method}"

        if verified:
            domain.is_verified = True
            domain.verified_at = datetime.utcnow()
            domain.verification_token = None
            domain.verification_token_expires = None
            await db.commit()
            return True, "Domain verified successfully"
        else:
            return False, f"Could not verify domain. Please ensure the {domain.verification_method} record is correctly set up."

    @staticmethod
    async def _verify_dns(domain_name: str, token: str) -> bool:
        """Verify domain ownership via DNS TXT record"""
        try:
            # Check for TXT record at _securesite-audit.domain.com
            txt_domain = f"_securesite-audit.{domain_name}"
            answers = dns.resolver.resolve(txt_domain, "TXT")
            for rdata in answers:
                txt_value = rdata.to_text().strip('"')
                if txt_value == token:
                    return True
            return False
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return False
        except Exception:
            return False

    @staticmethod
    async def _verify_file(domain_name: str, token: str) -> bool:
        """Verify domain ownership via file upload"""
        import httpx
        try:
            url = f"https://{domain_name}/.well-known/securesite-audit-verification.txt"
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    content = response.text.strip()
                    return content == token
            return False
        except Exception:
            return False

    @staticmethod
    async def _verify_meta(domain_name: str, token: str) -> bool:
        """Verify domain ownership via meta tag"""
        import httpx
        from html.parser import HTMLParser

        class MetaTagParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.found = False

            def handle_starttag(self, tag, attrs):
                if tag == "meta":
                    attrs_dict = dict(attrs)
                    if attrs_dict.get("name") == "securesite-audit-verification":
                        if attrs_dict.get("content") == token:
                            self.found = True

        try:
            url = f"https://{domain_name}"
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    parser = MetaTagParser()
                    parser.feed(response.text)
                    return parser.found
            return False
        except Exception:
            return False

    @staticmethod
    async def get_all_domains(db: AsyncSession):
        result = await db.execute(
            select(Domain).order_by(Domain.created_at.desc())
        )
        return result.scalars().all()

    @staticmethod
    async def get_domain_by_id(db: AsyncSession, domain_id: Any) -> Optional[Domain]:
        result = await db.execute(
            select(Domain).where(Domain.id == str(domain_id))
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def delete_domain(db: AsyncSession, domain_id: Any) -> bool:
        result = await db.execute(
            select(Domain).where(Domain.id == str(domain_id))
        )
        domain = result.scalar_one_or_none()
        if not domain:
            return False
        await db.delete(domain)
        await db.commit()
        return True