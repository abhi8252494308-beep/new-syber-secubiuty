import ssl
import socket
import httpx
import dns.resolver
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from uuid import UUID
from urllib.parse import urlparse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..config import settings
from ..models.audit import (
    Audit, AuditResult, TLSResult, HeaderResult, CookieResult,
    RobotsResult, SecurityTxtResult, ServerInfoResult,
    SSLabsResult, DNSResult, CORSResult, ClickjackingResult
)
from ..models.domain import Domain
from ..services.security_checks import SecurityScanner
from ..services.mongodb_service import get_mongodb_service


class AuditEngine:
    def __init__(self):
        self.timeout = settings.AUDIT_TIMEOUT_SECONDS
        self.results: List[AuditResult] = []
        self.total_score = 0
        self.max_possible_score = 0

    async def run_audit(self, db: AsyncSession, domain: Domain, audit_id: Optional[str] = None) -> Audit:
        """Run a complete security audit on a domain"""
        if audit_id:
            res = await db.execute(select(Audit).where(Audit.id == str(audit_id)))
            audit = res.scalar_one_or_none()
            if audit:
                audit.status = "running"
                audit.started_at = datetime.utcnow()
                audit.error_message = None
                await db.commit()
                await db.refresh(audit)
            else:
                audit = Audit(
                    id=str(audit_id),
                    domain_id=str(domain.id),
                    status="running",
                    started_at=datetime.utcnow(),
                )
                db.add(audit)
                await db.commit()
                await db.refresh(audit)
        else:
            audit = Audit(
                domain_id=str(domain.id),
                status="running",
                started_at=datetime.utcnow(),
            )
            db.add(audit)
            await db.commit()
            await db.refresh(audit)

        try:
            self.results = []
            self.total_score = 0
            self.max_possible_score = 0

            # Run all checks
            await self._check_https_tls(db, audit, domain.domain_name)
            await self._check_security_headers(db, audit, domain.domain_name)
            await self._check_cookies(db, audit, domain.domain_name)
            await self._check_robots_txt(db, audit, domain.domain_name)
            await self._check_security_txt(db, audit, domain.domain_name)
            await self._check_server_info(db, audit, domain.domain_name)
            
            # Run extended security checks
            await self._check_sslabs(db, audit, domain.domain_name)
            await self._check_dns_security(db, audit, domain.domain_name)
            await self._check_cors(db, audit, domain.domain_name)
            await self._check_clickjacking(db, audit, domain.domain_name)

            # Calculate overall score
            overall_score = 0
            if self.max_possible_score > 0:
                overall_score = int((self.total_score / self.max_possible_score) * 100)

            audit.status = "completed"
            audit.completed_at = datetime.utcnow()
            audit.overall_score = overall_score

            # Update domain's last audit time
            domain.last_audit_at = datetime.utcnow()

            # Save all results to SQL
            for result in self.results:
                db.add(result)

            await db.commit()
            await db.refresh(audit)
            
            # Save to MongoDB
            try:
                mongodb = await get_mongodb_service()
                await self._save_to_mongodb(mongodb, audit, domain.domain_name, overall_score)
            except Exception as e:
                print(f"Failed to save to MongoDB: {e}")

        except Exception as e:
            audit.status = "failed"
            audit.completed_at = datetime.utcnow()
            audit.error_message = str(e)
            await db.commit()

        return audit

    async def _save_to_mongodb(self, mongodb, audit: Audit, domain_name: str, overall_score: int):
        """Save audit results to MongoDB"""
        # Build result document
        result_doc = {
            "audit_id": audit.id,
            "domain": domain_name,
            "status": audit.status,
            "overall_score": overall_score,
            "risk_score": getattr(audit, 'risk_score', 0),
            "started_at": audit.started_at,
            "completed_at": audit.completed_at,
            "created_at": audit.created_at,
            "updated_at": audit.updated_at,
        }
        
        # Add individual check results
        for result in self.results:
            result_doc[f"{result.check_category}_result"] = {
                "check_name": result.check_name,
                "status": result.status,
                "score": result.score,
                "max_score": result.max_score,
                "details": result.details,
                "recommendations": result.recommendations,
            }
        
        # Add extended results if available
        if audit.sslabs_result:
            result_doc["sslabs"] = {
                "grade": audit.sslabs_result.grade,
                "vulnerabilities": audit.sslabs_result.vulnerabilities,
                "protocols": audit.sslabs_result.protocols,
                "cipher_strength": audit.sslabs_result.cipher_strength,
            }
        
        if audit.dns_result:
            result_doc["dns_security"] = {
                "spf_record": audit.dns_result.spf_record,
                "spf_valid": audit.dns_result.spf_valid,
                "spf_mechanisms": audit.dns_result.spf_mechanisms,
                "dkim_records": audit.dns_result.dkim_records,
                "dkim_count": audit.dns_result.dkim_count,
                "dmarc_record": audit.dns_result.dmarc_record,
                "dmarc_policy": audit.dns_result.dmarc_policy,
                "dmarc_valid": audit.dns_result.dmarc_valid,
            }
        
        if audit.cors_result:
            result_doc["cors"] = {
                "wildcard_origin": audit.cors_result.wildcard_origin,
                "allows_credentials": audit.cors_result.allows_credentials,
                "allowed_methods": audit.cors_result.allowed_methods,
                "allowed_headers": audit.cors_result.allowed_headers,
                "exposed_headers": audit.cors_result.exposed_headers,
                "max_age": audit.cors_result.max_age,
                "issues": audit.cors_result.issues,
            }
        
        if audit.clickjacking_result:
            result_doc["clickjacking"] = {
                "vulnerable": audit.clickjacking_result.vulnerable,
                "x_frame_options": audit.clickjacking_result.x_frame_options,
                "csp_frame_ancestors": audit.clickjacking_result.csp_frame_ancestors,
                "content_security_policy": audit.clickjacking_result.content_security_policy,
                "details": audit.clickjacking_result.details,
            }
        
        await mongodb.save_audit_result(result_doc)

    async def _check_https_tls(self, db: AsyncSession, audit: Audit, domain: str):
        """Check HTTPS/TLS configuration"""
        tls_result = TLSResult(audit_id=audit.id)
        score = 0
        max_score = 0

        try:
            # Check if HTTPS is available
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                try:
                    response = await client.get(f"https://{domain}")
                    tls_result.has_https = True
                    score += 10
                except Exception as e:
                    print(f"HTTPS check error: {e}")
                    tls_result.has_https = False

            max_score += 10

            # Get SSL certificate info
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        tls_result.tls_version = ssock.version()
                        tls_result.cipher_suite = ssock.cipher()[0]

                        # Certificate validity
                        not_after = cert.get("notAfter")
                        not_before = cert.get("notBefore")
                        if not_after and not_before:
                            tls_result.certificate_not_after = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            tls_result.certificate_not_before = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                            days_remaining = (tls_result.certificate_not_after - datetime.utcnow()).days
                            tls_result.certificate_days_remaining = days_remaining
                            tls_result.certificate_valid = days_remaining > 0

                            if days_remaining > 30:
                                score += 10
                            elif days_remaining > 7:
                                score += 5
                            max_score += 10

                        # Certificate issuer
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        tls_result.certificate_issuer = issuer.get("organizationName", "")

                        # Certificate subject
                        subject = dict(x[0] for x in cert.get("subject", []))
                        tls_result.certificate_subject = subject.get("commonName", "")

                        # Subject Alternative Names
                        san = cert.get("subjectAltName", [])
                        tls_result.certificate_san = [x[1] for x in san] if san else []

            except Exception as e:
                print(f"SSL certificate check error: {e}")
                tls_result.certificate_valid = False

            # Check HSTS
            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                    response = await client.get(f"https://{domain}")
                    hsts_header = response.headers.get("strict-transport-security")
                    if hsts_header:
                        tls_result.hsts_enabled = True
                        score += 10

                        # Parse max-age
                        parts = hsts_header.split(";")
                        for part in parts:
                            part = part.strip()
                            if part.startswith("max-age="):
                                try:
                                    tls_result.hsts_max_age = int(part.split("=")[1])
                                except ValueError:
                                    pass
                            elif part.strip() == "includeSubDomains":
                                tls_result.hsts_include_subdomains = True
                            elif part.strip() == "preload":
                                tls_result.hsts_preload = True

                        if tls_result.hsts_include_subdomains:
                            score += 5
                        if tls_result.hsts_preload:
                            score += 5
                        max_score += 20
            except Exception as e:
                print(f"HSTS check error: {e}")

        except Exception as e:
            print(f"TLS check error: {e}")

        db.add(tls_result)

        # Add audit result
        self._add_result(
            audit.id, "tls", "HTTPS/TLS Configuration",
            "pass" if tls_result.has_https else "fail",
            score, max_score,
            {
                "has_https": tls_result.has_https,
                "tls_version": tls_result.tls_version,
                "certificate_valid": tls_result.certificate_valid,
                "certificate_days_remaining": tls_result.certificate_days_remaining,
                "hsts_enabled": tls_result.hsts_enabled,
            },
            self._get_tls_recommendations(tls_result),
        )

    async def _check_security_headers(self, db: AsyncSession, audit: Audit, domain: str):
        """Check security headers"""
        header_result = HeaderResult(audit_id=audit.id)
        score = 0
        max_score = 0

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(f"https://{domain}")
                headers = response.headers

                # Content Security Policy
                csp = headers.get("content-security-policy")
                if csp:
                    header_result.content_security_policy = csp
                    header_result.csp_valid = "unsafe-inline" not in csp and "unsafe-eval" not in csp
                    score += 10 if header_result.csp_valid else 5
                max_score += 10

                # X-Frame-Options
                x_frame = headers.get("x-frame-options")
                if x_frame:
                    header_result.x_frame_options = x_frame
                    score += 10
                max_score += 10

                # X-Content-Type-Options
                x_content_type = headers.get("x-content-type-options")
                if x_content_type:
                    header_result.x_content_type_options = x_content_type
                    score += 10
                max_score += 10

                # X-XSS-Protection
                xss_protection = headers.get("x-xss-protection")
                if xss_protection:
                    header_result.x_xss_protection = xss_protection
                    score += 5
                max_score += 5

                # Referrer-Policy
                referrer_policy = headers.get("referrer-policy")
                if referrer_policy:
                    header_result.referrer_policy = referrer_policy
                    score += 5
                max_score += 5

                # Permissions-Policy
                permissions_policy = headers.get("permissions-policy")
                if permissions_policy:
                    header_result.permissions_policy = permissions_policy
                    score += 5
                max_score += 5

                # Cross-Origin headers
                coop = headers.get("cross-origin-opener-policy")
                if coop:
                    header_result.cross_origin_opener_policy = coop
                    score += 5
                max_score += 5

                corp = headers.get("cross-origin-resource-policy")
                if corp:
                    header_result.cross_origin_resource_policy = corp
                    score += 5
                max_score += 5

                coep = headers.get("cross-origin-embedder-policy")
                if coep:
                    header_result.cross_origin_embedder_policy = coep
                    score += 5
                max_score += 5

        except Exception as e:
            print(f"Security headers check error: {e}")

        db.add(header_result)

        self._add_result(
            audit.id, "headers", "Security Headers",
            "pass" if score > max_score * 0.5 else "fail",
            score, max_score,
            {
                "csp_valid": header_result.csp_valid,
                "x_frame_options": header_result.x_frame_options,
                "x_content_type_options": header_result.x_content_type_options,
            },
            self._get_header_recommendations(header_result),
        )

    async def _check_cookies(self, db: AsyncSession, audit: Audit, domain: str):
        """Check cookie security flags"""
        score = 0
        max_score = 0
        cookie_results = []

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(f"https://{domain}")
                cookies = response.cookies

                # Get all Set-Cookie headers (httpx returns them as a list)
                set_cookie_headers = response.headers.get_list("set-cookie")

                for cookie_name, cookie_value in cookies.items():
                    cookie_result = CookieResult(
                        audit_id=audit.id,
                        cookie_name=cookie_name,
                    )

                    # Check cookie attributes from Set-Cookie headers
                    for set_cookie in set_cookie_headers:
                        if cookie_name in set_cookie:
                            cookie_lower = set_cookie.lower()
                            cookie_result.has_secure_flag = "secure" in cookie_lower
                            cookie_result.has_httponly_flag = "httponly" in cookie_lower
                            cookie_result.has_samesite_flag = "samesite" in cookie_lower

                            if "samesite=strict" in cookie_lower:
                                cookie_result.samesite_value = "Strict"
                            elif "samesite=lax" in cookie_lower:
                                cookie_result.samesite_value = "Lax"
                            break

                    cookie_score = 0
                    cookie_max = 3

                    if cookie_result.has_secure_flag:
                        cookie_score += 1
                    if cookie_result.has_httponly_flag:
                        cookie_score += 1
                    if cookie_result.has_samesite_flag:
                        cookie_score += 1

                    score += cookie_score
                    max_score += cookie_max

                    cookie_results.append(cookie_result)
                    db.add(cookie_result)

        except Exception as e:
            print(f"Cookie check error: {e}")

        if not cookie_results:
            # No cookies found - add a placeholder result
            cookie_result = CookieResult(
                audit_id=audit.id,
                cookie_name="none",
                has_secure_flag=True,
                has_httponly_flag=True,
                has_samesite_flag=True,
            )
            db.add(cookie_result)
            cookie_results.append(cookie_result)

        self._add_result(
            audit.id, "cookies", "Cookie Security",
            "pass" if score >= max_score * 0.7 else "fail",
            score, max_score if max_score > 0 else 1,
            {"cookie_count": len(cookie_results)},
            self._get_cookie_recommendations(cookie_results),
        )

    async def _check_robots_txt(self, db: AsyncSession, audit: Audit, domain: str):
        """Check robots.txt presence and content"""
        robots_result = RobotsResult(audit_id=audit.id)
        score = 0
        max_score = 10

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(f"https://{domain}/robots.txt")
                if response.status_code == 200:
                    robots_result.exists = True
                    robots_result.content = response.text
                    score += 5

                    # Check for sitemap references
                    sitemap_urls = []
                    for line in response.text.split("\n"):
                        line = line.strip()
                        if line.lower().startswith("sitemap:"):
                            sitemap_urls.append(line.split(":", 1)[1].strip())
                        elif line.lower().startswith("security:"):
                            robots_result.has_security_txt_reference = True
                    robots_result.sitemap_urls = sitemap_urls

                    if sitemap_urls:
                        score += 3
                    if robots_result.has_security_txt_reference:
                        score += 2

        except Exception as e:
            print(f"robots.txt check error: {e}")

        db.add(robots_result)

        self._add_result(
            audit.id, "robots", "robots.txt",
            "pass" if robots_result.exists else "fail",
            score, max_score,
            {
                "exists": robots_result.exists,
                "has_sitemap": bool(robots_result.sitemap_urls),
                "has_security_txt_reference": robots_result.has_security_txt_reference,
            },
            ["Add a robots.txt file to your website"] if not robots_result.exists else [],
        )

    async def _check_security_txt(self, db: AsyncSession, audit: Audit, domain: str):
        """Check security.txt presence and content"""
        security_txt_result = SecurityTxtResult(audit_id=audit.id)
        score = 0
        max_score = 10

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                # Check well-known location first
                response = await client.get(f"https://{domain}/.well-known/security.txt")
                if response.status_code != 200:
                    response = await client.get(f"https://{domain}/security.txt")

                if response.status_code == 200:
                    security_txt_result.exists = True
                    security_txt_result.content = response.text
                    score += 5

                    # Parse security.txt fields
                    contact_urls = []
                    encryption_urls = []
                    policy_urls = []
                    acknowledged_urls = []

                    for line in response.text.split("\n"):
                        line = line.strip()
                        if line.lower().startswith("contact:"):
                            contact_urls.append(line.split(":", 1)[1].strip())
                        elif line.lower().startswith("encryption:"):
                            encryption_urls.append(line.split(":", 1)[1].strip())
                        elif line.lower().startswith("policy:"):
                            policy_urls.append(line.split(":", 1)[1].strip())
                        elif line.lower().startswith("acknowledgements:"):
                            acknowledged_urls.append(line.split(":", 1)[1].strip())
                        elif line.lower().startswith("expires:"):
                            try:
                                expires_str = line.split(":", 1)[1].strip()
                                security_txt_result.expires = datetime.strptime(expires_str, "%Y-%m-%dT%H:%M:%S%z")
                            except ValueError:
                                pass

                    security_txt_result.contact_urls = contact_urls
                    security_txt_result.encryption_urls = encryption_urls
                    security_txt_result.policy_urls = policy_urls
                    security_txt_result.acknowledged_urls = acknowledged_urls

                    if contact_urls:
                        score += 3
                    if encryption_urls:
                        score += 1
                    if policy_urls:
                        score += 1

        except Exception as e:
            print(f"security.txt check error: {e}")

        db.add(security_txt_result)

        self._add_result(
            audit.id, "security_txt", "security.txt",
            "pass" if security_txt_result.exists else "fail",
            score, max_score,
            {
                "exists": security_txt_result.exists,
                "has_contact": bool(security_txt_result.contact_urls),
                "has_encryption": bool(security_txt_result.encryption_urls),
            },
            ["Add a security.txt file to your website"] if not security_txt_result.exists else [],
        )

    async def _check_server_info(self, db: AsyncSession, audit: Audit, domain: str):
        """Check publicly exposed server information"""
        server_info_result = ServerInfoResult(audit_id=audit.id)
        score = 10
        max_score = 10

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(f"https://{domain}")
                headers = response.headers

                # Check Server header
                server_header = headers.get("server")
                if server_header:
                    server_info_result.server_header = server_header
                    # Deduct points for exposing server version
                    if "/" in server_header:
                        score -= 5

                # Check X-Powered-By header
                powered_by = headers.get("x-powered-by")
                if powered_by:
                    server_info_result.x_powered_by = powered_by
                    score -= 5

                # Detect technology stack
                tech_stack = {}
                if server_header:
                    tech_stack["server"] = server_header
                if powered_by:
                    tech_stack["powered_by"] = powered_by

                # Check for common technology indicators
                if "x-generator" in headers:
                    tech_stack["generator"] = headers["x-generator"]
                if "x-aspnet-version" in headers:
                    tech_stack["aspnet_version"] = headers["x-aspnet-version"]
                if "x-drupal-cache" in headers:
                    tech_stack["cms"] = "Drupal"
                if "x-varnish" in headers:
                    tech_stack["cache"] = "Varnish"

                server_info_result.technology_stack = tech_stack

                # Get IP address
                try:
                    answers = dns.resolver.resolve(domain, "A")
                    if answers:
                        server_info_result.ip_address = str(answers[0])
                except Exception as e:
                    print(f"DNS resolution error: {e}")

        except Exception as e:
            print(f"Server info check error: {e}")

        db.add(server_info_result)

        self._add_result(
            audit.id, "server_info", "Server Information Exposure",
            "pass" if score >= 7 else "fail",
            score, max_score,
            {
                "server_header": server_info_result.server_header,
                "x_powered_by": server_info_result.x_powered_by,
                "technology_stack": server_info_result.technology_stack,
            },
            self._get_server_info_recommendations(server_info_result),
        )

    def _add_result(
        self,
        audit_id: UUID,
        category: str,
        name: str,
        status: str,
        score: int,
        max_score: int,
        details: Dict[str, Any],
        recommendations: List[str],
    ):
        """Add an audit result"""
        result = AuditResult(
            audit_id=audit_id,
            check_category=category,
            check_name=name,
            status=status,
            score=score,
            max_score=max_score,
            details=details,
            recommendations=recommendations,
        )
        self.results.append(result)
        self.total_score += score
        self.max_possible_score += max_score

    def _get_tls_recommendations(self, tls_result: TLSResult) -> List[str]:
        recs = []
        if not tls_result.has_https:
            recs.append("Enable HTTPS for your website")
        if not tls_result.certificate_valid:
            recs.append("Your SSL certificate is invalid or expired")
        if tls_result.certificate_days_remaining is not None and tls_result.certificate_days_remaining < 30:
            recs.append(f"Your SSL certificate expires in {tls_result.certificate_days_remaining} days")
        if not tls_result.hsts_enabled:
            recs.append("Enable HTTP Strict Transport Security (HSTS)")
        elif not tls_result.hsts_include_subdomains:
            recs.append("Consider adding includeSubDomains to your HSTS header")
        return recs

    def _get_header_recommendations(self, header_result: HeaderResult) -> List[str]:
        recs = []
        if not header_result.content_security_policy:
            recs.append("Add a Content Security Policy (CSP) header")
        elif not header_result.csp_valid:
            recs.append("Your CSP contains unsafe directives (unsafe-inline, unsafe-eval)")
        if not header_result.x_frame_options:
            recs.append("Add X-Frame-Options header to prevent clickjacking")
        if not header_result.x_content_type_options:
            recs.append("Add X-Content-Type-Options: nosniff header")
        if not header_result.x_xss_protection:
            recs.append("Add X-XSS-Protection header")
        if not header_result.referrer_policy:
            recs.append("Add a Referrer-Policy header")
        if not header_result.permissions_policy:
            recs.append("Add a Permissions-Policy header")
        return recs

    def _get_cookie_recommendations(self, cookie_results: List[CookieResult]) -> List[str]:
        recs = []
        for cookie in cookie_results:
            if cookie.cookie_name == "none":
                return recs
            if not cookie.has_secure_flag:
                recs.append(f"Add Secure flag to cookie: {cookie.cookie_name}")
            if not cookie.has_httponly_flag:
                recs.append(f"Add HttpOnly flag to cookie: {cookie.cookie_name}")
            if not cookie.has_samesite_flag:
                recs.append(f"Add SameSite attribute to cookie: {cookie.cookie_name}")
        return recs

    def _get_server_info_recommendations(self, server_info_result: ServerInfoResult) -> List[str]:
        recs = []
        if server_info_result.server_header and "/" in server_info_result.server_header:
            recs.append("Remove version information from Server header")
        if server_info_result.x_powered_by:
            recs.append("Remove X-Powered-By header to hide technology information")
        return recs

    async def _check_sslabs(self, db: AsyncSession, audit: Audit, domain: str):
        """Run SSL Labs comprehensive analysis"""
        sslabs_result = SSLabsResult(audit_id=audit.id)
        score = 0
        max_score = 100
        
        try:
            scanner = SecurityScanner()
            result = await scanner._run_sslabs(domain)
            
            if "error" not in result:
                sslabs_result.grade = result.get("grade", "F")
                sslabs_result.vulnerabilities = result.get("vulnerabilities", [])
                sslabs_result.protocols = result.get("protocols", {})
                sslabs_result.cipher_strength = result.get("cipher_strength", {})
                
                # Score based on grade
                grade_scores = {"A+": 100, "A": 95, "A-": 90, "B": 70, "C": 50, "D": 30, "E": 20, "F": 0}
                score = grade_scores.get(result.get("grade", "F"), 0)
                
                # Deduct for vulnerabilities
                vulns = result.get("vulnerabilities", [])
                critical_vulns = [v for v in vulns if v.get("severity") == "CRITICAL"]
                high_vulns = [v for v in vulns if v.get("severity") == "HIGH"]
                score -= len(critical_vulns) * 15
                score -= len(high_vulns) * 10
                score = max(score, 0)
            
            await scanner.close()
        
        except Exception as e:
            print(f"SSL Labs check error: {e}")
        
        db.add(sslabs_result)
        
        self._add_result(
            audit.id, "sslabs", "SSL Labs Analysis",
            "pass" if score >= 70 else "fail",
            score, max_score,
            {
                "grade": sslabs_result.grade,
                "vulnerability_count": len(sslabs_result.vulnerabilities) if sslabs_result.vulnerabilities else 0,
                "protocols": sslabs_result.protocols,
                "cipher_strength": sslabs_result.cipher_strength,
            },
            self._get_sslabs_recommendations(sslabs_result),
        )

    async def _check_dns_security(self, db: AsyncSession, audit: Audit, domain: str):
        """Run DNS security checks (SPF, DKIM, DMARC)"""
        dns_result = DNSResult(audit_id=audit.id)
        score = 0
        max_score = 100
        
        try:
            scanner = SecurityScanner()
            result = await scanner._run_dns_checks(domain)
            
            if "error" not in result:
                dns_result.spf_record = result.get("spf", {}).get("record")
                dns_result.spf_valid = result.get("spf", {}).get("valid", False)
                dns_result.spf_mechanisms = result.get("spf", {}).get("mechanisms", [])
                
                dns_result.dkim_records = result.get("dkim", {}).get("records", [])
                dns_result.dkim_count = result.get("dkim", {}).get("count", 0)
                
                dns_result.dmarc_record = result.get("dmarc", {}).get("record")
                dns_result.dmarc_policy = result.get("dmarc", {}).get("policy", "none")
                dns_result.dmarc_valid = result.get("dmarc", {}).get("valid", False)
                
                score = result.get("overall_score", 0)
            
            await scanner.close()
        
        except Exception as e:
            print(f"DNS security check error: {e}")
        
        db.add(dns_result)
        
        self._add_result(
            audit.id, "dns", "DNS Security (SPF/DKIM/DMARC)",
            "pass" if score >= 70 else "fail",
            score, max_score,
            {
                "spf_exists": dns_result.spf_record is not None,
                "spf_valid": dns_result.spf_valid,
                "dkim_count": dns_result.dkim_count,
                "dmarc_policy": dns_result.dmarc_policy,
                "dmarc_valid": dns_result.dmarc_valid,
            },
            self._get_dns_recommendations(dns_result),
        )

    async def _check_cors(self, db: AsyncSession, audit: Audit, domain: str):
        """Run CORS configuration analysis"""
        cors_result = CORSResult(audit_id=audit.id)
        score = 100
        max_score = 100
        
        try:
            scanner = SecurityScanner()
            result = await scanner._run_cors_checks(domain)
            
            if "error" not in result:
                cors_result.wildcard_origin = result.get("wildcard_origin", False)
                cors_result.allows_credentials = result.get("allows_credentials", False)
                cors_result.allowed_methods = result.get("allowed_methods", [])
                cors_result.allowed_headers = result.get("allowed_headers", [])
                cors_result.exposed_headers = result.get("exposed_headers", [])
                cors_result.max_age = result.get("max_age")
                cors_result.issues = result.get("issues", [])
                
                # Deduct for issues
                score -= len(result.get("issues", [])) * 15
                score = max(score, 0)
            
            await scanner.close()
        
        except Exception as e:
            print(f"CORS check error: {e}")
        
        db.add(cors_result)
        
        self._add_result(
            audit.id, "cors", "CORS Configuration",
            "pass" if score >= 70 else "fail",
            score, max_score,
            {
                "wildcard_origin": cors_result.wildcard_origin,
                "allows_credentials": cors_result.allows_credentials,
                "allowed_methods": cors_result.allowed_methods,
                "issues": cors_result.issues,
            },
            self._get_cors_recommendations(cors_result),
        )

    async def _check_clickjacking(self, db: AsyncSession, audit: Audit, domain: str):
        """Run clickjacking detection"""
        cj_result = ClickjackingResult(audit_id=audit.id)
        score = 0
        max_score = 10
        
        try:
            scanner = SecurityScanner()
            result = await scanner._run_clickjacking_check(domain)
            
            if "error" not in result:
                cj_result.vulnerable = result.get("vulnerable", True)
                cj_result.x_frame_options = result.get("x_frame_options")
                cj_result.csp_frame_ancestors = result.get("csp_frame_ancestors")
                cj_result.content_security_policy = result.get("content_security_policy")
                cj_result.details = result.get("details", [])
                
                score = 10 if not result.get("vulnerable", True) else 0
            
            await scanner.close()
        
        except Exception as e:
            print(f"Clickjacking check error: {e}")
        
        db.add(cj_result)
        
        self._add_result(
            audit.id, "clickjacking", "Clickjacking Protection",
            "pass" if score >= 7 else "fail",
            score, max_score,
            {
                "vulnerable": cj_result.vulnerable,
                "x_frame_options": cj_result.x_frame_options,
                "csp_frame_ancestors": cj_result.csp_frame_ancestors,
            },
            self._get_clickjacking_recommendations(cj_result),
        )

    def _get_sslabs_recommendations(self, sslabs_result: SSLabsResult) -> List[str]:
        recs = []
        grade = sslabs_result.grade or "F"
        if grade in ["F", "E", "D"]:
            recs.append(f"SSL grade is {grade} - immediate attention required")
        elif grade in ["C", "B"]:
            recs.append(f"SSL grade is {grade} - improvements recommended")
        
        for vuln in sslabs_result.vulnerabilities or []:
            if vuln.get("severity") in ["CRITICAL", "HIGH"]:
                recs.append(f"Address {vuln.get('name')}: {vuln.get('details')}")
        
        if sslabs_result.protocols:
            old_protocols = [p for p in sslabs_result.protocols if p in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]]
            if old_protocols:
                recs.append(f"Disable deprecated protocols: {', '.join(old_protocols)}")
        
        return recs

    def _get_dns_recommendations(self, dns_result: DNSResult) -> List[str]:
        recs = []
        if not dns_result.spf_record:
            recs.append("Add SPF record to prevent email spoofing")
        elif not dns_result.spf_valid:
            recs.append("Fix SPF record - missing 'all' mechanism")
        
        if dns_result.dkim_count == 0:
            recs.append("Add DKIM records for email signing")
        
        if not dns_result.dmarc_record:
            recs.append("Add DMARC record for email authentication policy")
        elif dns_result.dmarc_policy == "none":
            recs.append("Set DMARC policy to 'quarantine' or 'reject' for better protection")
        elif not dns_result.dmarc_valid:
            recs.append("Fix DMARC record configuration")
        
        return recs

    def _get_cors_recommendations(self, cors_result: CORSResult) -> List[str]:
        recs = []
        for issue in cors_result.issues or []:
            recs.append(issue)
        if not cors_result.issues:
            recs.append("CORS configuration appears secure")
        return recs

    def _get_clickjacking_recommendations(self, cj_result: ClickjackingResult) -> List[str]:
        recs = []
        if cj_result.vulnerable:
            if not cj_result.x_frame_options:
                recs.append("Add X-Frame-Options header (DENY or SAMEORIGIN)")
            if not cj_result.csp_frame_ancestors:
                recs.append("Add Content-Security-Policy with frame-ancestors directive")
        else:
            recs.append("Clickjacking protection is properly configured")
        return recs