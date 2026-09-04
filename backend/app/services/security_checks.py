import asyncio
import dns.resolver
import httpx
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from urllib.parse import urlparse


class SSLabsAPI:
    """SSL Labs API integration for comprehensive SSL/TLS testing"""
    
    BASE_URL = "https://api.ssllabs.com/api/v3"
    
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=300.0)
    
    async def analyze(self, host: str, publish: bool = False, start_new: bool = True, 
                     from_cache: bool = False, max_age: int = 24) -> Dict[str, Any]:
        """Start or retrieve SSL Labs analysis"""
        params = {
            "host": host,
            "publish": "on" if publish else "off",
            "startNew": "on" if start_new else "off",
            "fromCache": "on" if from_cache else "off",
            "maxAge": max_age,
        }
        
        response = await self.client.get(f"{self.BASE_URL}/analyze", params=params)
        response.raise_for_status()
        return response.json()
    
    async def wait_for_completion(self, host: str, max_wait: int = 240) -> Dict[str, Any]:
        """Poll until analysis is complete"""
        start_time = datetime.utcnow()
        
        while True:
            result = await self.analyze(host, from_cache=True)
            status = result.get("status", "")
            
            if status in ["READY", "ERROR"]:
                return result
            
            if (datetime.utcnow() - start_time).seconds > max_wait:
                return {"status": "TIMEOUT", "error": "Analysis timed out"}
            
            await asyncio.sleep(30)
    
    def get_grade(self, result: Dict[str, Any]) -> str:
        """Extract overall grade from SSL Labs result"""
        endpoints = result.get("endpoints", [])
        if not endpoints:
            return "F"
        grades = [e.get("grade", "F") for e in endpoints]
        return max(grades) if grades else "F"
    
    def get_vulnerabilities(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from SSL Labs result"""
        vulns = []
        for endpoint in result.get("endpoints", []):
            for vuln in endpoint.get("vulnerabilities", []):
                vulns.append({
                    "name": vuln.get("name", ""),
                    "severity": vuln.get("severity", ""),
                    "details": vuln.get("details", ""),
                })
        return vulns
    
    def get_protocol_support(self, result: Dict[str, Any]) -> Dict[str, bool]:
        """Extract supported protocols"""
        protocols = {}
        for endpoint in result.get("endpoints", []):
            for suite in endpoint.get("details", {}).get("suites", {}).get("list", []):
                protocol = suite.get("protocol", "")
                if protocol:
                    protocols[protocol] = True
        return protocols
    
    def get_cipher_strength(self, result: Dict[str, Any]) -> Dict[str, int]:
        """Extract cipher strength statistics"""
        strong = 0
        weak = 0
        for endpoint in result.get("endpoints", []):
            for suite in endpoint.get("details", {}).get("suites", {}).get("list", []):
                if suite.get("kx") and suite.get("enc"):
                    strength = suite.get("enc", {}).get("bits", 0)
                    if strength >= 128:
                        strong += 1
                    else:
                        weak += 1
        return {"strong": strong, "weak": weak}
    
    async def close(self):
        await self.client.aclose()


class DNSSecurityChecker:
    """DNS security checks for SPF, DKIM, DMARC"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 10
    
    async def check_spf(self, domain: str) -> Dict[str, Any]:
        """Check SPF record"""
        try:
            answers = self.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    return {
                        "exists": True,
                        "record": txt,
                        "valid": self._validate_spf(txt),
                        "mechanisms": self._parse_spf_mechanisms(txt),
                    }
            return {"exists": False, "record": None, "valid": False, "mechanisms": []}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return {"exists": False, "record": None, "valid": False, "mechanisms": []}
        except Exception as e:
            return {"exists": False, "error": str(e)}
    
    def _validate_spf(self, spf_record: str) -> bool:
        """Basic SPF validation"""
        parts = spf_record.split()
        if not parts or parts[0] != "v=spf1":
            return False
        
        has_all = any(p in ["-all", "~all", "+all", "?all"] for p in parts[1:])
        return has_all
    
    def _parse_spf_mechanisms(self, spf_record: str) -> List[str]:
        """Parse SPF mechanisms"""
        mechanisms = []
        parts = spf_record.split()
        for part in parts[1:]:
            if part.startswith(("ip4:", "ip6:", "a", "mx", "include:", "exists:", "ptr")):
                mechanisms.append(part)
        return mechanisms
    
    async def check_dkim(self, domain: str, selectors: Optional[List[str]] = None) -> Dict[str, Any]:
        """Check DKIM records for common selectors"""
        if selectors is None:
            selectors = ["default", "google", "selector1", "selector2", "k1", "k2", 
                        "mail", "email", "dkim", "s1", "s2"]
        
        results = []
        for selector in selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = self.resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    if "v=DKIM1" in txt or "p=" in txt:
                        results.append({
                            "selector": selector,
                            "exists": True,
                            "record": txt[:200],
                        })
                        break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except Exception:
                continue
        
        return {"records": results, "count": len(results)}
    
    async def check_dmarc(self, domain: str) -> Dict[str, Any]:
        """Check DMARC record"""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    return {
                        "exists": True,
                        "record": txt,
                        "policy": self._parse_dmarc_policy(txt),
                        "valid": self._validate_dmarc(txt),
                    }
            return {"exists": False, "record": None, "policy": "none", "valid": False}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return {"exists": False, "record": None, "policy": "none", "valid": False}
        except Exception as e:
            return {"exists": False, "error": str(e)}
    
    def _parse_dmarc_policy(self, dmarc_record: str) -> str:
        """Extract DMARC policy"""
        parts = dmarc_record.split(";")
        for part in parts:
            part = part.strip()
            if part.startswith("p="):
                return part.split("=")[1]
        return "none"
    
    def _validate_dmarc(self, dmarc_record: str) -> bool:
        """Basic DMARC validation"""
        return "v=DMARC1" in dmarc_record and "p=" in dmarc_record
    
    async def check_all(self, domain: str) -> Dict[str, Any]:
        """Run all DNS security checks"""
        spf = await self.check_spf(domain)
        dkim = await self.check_dkim(domain)
        dmarc = await self.check_dmarc(domain)
        
        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "overall_score": self._calculate_score(spf, dkim, dmarc),
        }
    
    def _calculate_score(self, spf: Dict, dkim: Dict, dmarc: Dict) -> int:
        """Calculate DNS security score (0-100)"""
        score = 0
        if spf.get("exists") and spf.get("valid"):
            score += 30
        elif spf.get("exists"):
            score += 15
        
        if dkim.get("count", 0) > 0:
            score += 35
        elif dkim.get("count", 0) > 1:
            score += 35
        
        if dmarc.get("exists") and dmarc.get("valid"):
            score += 35
        elif dmarc.get("exists"):
            score += 20
        
        return min(score, 100)


class CORSChecker:
    """CORS configuration analysis"""
    
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
    
    async def check_cors(self, url: str) -> Dict[str, Any]:
        """Check CORS configuration"""
        results = {
            "wildcard_origin": False,
            "allows_credentials": False,
            "exposed_headers": [],
            "allowed_methods": [],
            "allowed_headers": [],
            "max_age": None,
            "issues": [],
        }
        
        try:
            # Test preflight request
            response = await self.client.options(
                url,
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type",
                }
            )
            
            acao = response.headers.get("access-control-allow-origin")
            acac = response.headers.get("access-control-allow-credentials")
            acam = response.headers.get("access-control-allow-methods")
            acah = response.headers.get("access-control-allow-headers")
            acma = response.headers.get("access-control-max-age")
            aceh = response.headers.get("access-control-expose-headers")
            
            if acao == "*":
                results["wildcard_origin"] = True
                results["issues"].append("Wildcard origin (*) allowed - security risk")
            
            if acao and "evil.com" in acao:
                results["wildcard_origin"] = True
                results["issues"].append("Reflects arbitrary origin - security risk")
            
            if acac and acac.lower() == "true":
                results["allows_credentials"] = True
                if results["wildcard_origin"]:
                    results["issues"].append("Credentials allowed with wildcard origin - critical security risk")
            
            if acam:
                results["allowed_methods"] = [m.strip() for m in acam.split(",")]
            
            if acah:
                results["allowed_headers"] = [h.strip() for h in acah.split(",")]
            
            if acma:
                try:
                    results["max_age"] = int(acma)
                except ValueError:
                    pass
            
            if aceh:
                results["exposed_headers"] = [h.strip() for h in aceh.split(",")]
        
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    async def check_multiple_origins(self, url: str, origins: List[str]) -> Dict[str, Any]:
        """Test CORS with multiple origins"""
        results = {}
        for origin in origins:
            try:
                response = await self.client.options(
                    url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "POST",
                    }
                )
                acao = response.headers.get("access-control-allow-origin")
                results[origin] = {
                    "allowed": acao == origin or acao == "*",
                    "returned_origin": acao,
                }
            except Exception as e:
                results[origin] = {"error": str(e)}
        return results
    
    async def close(self):
        await self.client.aclose()


class ClickjackingChecker:
    """Clickjacking detection via iframe test"""
    
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
    
    async def check(self, url: str) -> Dict[str, Any]:
        """Check for clickjacking protection"""
        result = {
            "vulnerable": False,
            "x_frame_options": None,
            "csp_frame_ancestors": None,
            "content_security_policy": None,
            "details": [],
        }
        
        try:
            response = await self.client.get(url)
            headers = response.headers
            
            # Check X-Frame-Options
            xfo = headers.get("x-frame-options", "").upper()
            result["x_frame_options"] = xfo if xfo else None
            
            if xfo in ["DENY", "SAMEORIGIN"]:
                result["details"].append(f"X-Frame-Options: {xfo} - Protected")
            elif xfo:
                result["details"].append(f"X-Frame-Options: {xfo} - May not be fully protected")
            else:
                result["details"].append("X-Frame-Options: Missing")
                result["vulnerable"] = True
            
            # Check CSP frame-ancestors
            csp = headers.get("content-security-policy", "")
            result["content_security_policy"] = csp if csp else None
            
            if csp:
                import re
                frame_ancestors_match = re.search(r"frame-ancestors\s+([^;]+)", csp)
                if frame_ancestors_match:
                    result["csp_frame_ancestors"] = frame_ancestors_match.group(1).strip()
                    if "'none'" in result["csp_frame_ancestors"] or "'self'" in result["csp_frame_ancestors"]:
                        result["details"].append(f"CSP frame-ancestors: {result['csp_frame_ancestors']} - Protected")
                    else:
                        result["details"].append(f"CSP frame-ancestors: {result['csp_frame_ancestors']} - May allow framing")
                else:
                    result["details"].append("CSP present but no frame-ancestors directive")
            
            # Determine overall vulnerability
            if result["x_frame_options"] in ["DENY", "SAMEORIGIN"]:
                result["vulnerable"] = False
            elif result["csp_frame_ancestors"] and ("'none'" in result["csp_frame_ancestors"] or "'self'" in result["csp_frame_ancestors"]):
                result["vulnerable"] = False
            else:
                result["vulnerable"] = True
        
        except Exception as e:
            result["error"] = str(e)
            result["vulnerable"] = True
        
        return result
    
    async def generate_test_page(self, target_url: str) -> str:
        """Generate HTML test page for manual clickjacking verification"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Test - {target_url}</title>
    <style>
        body {{ font-family: sans-serif; padding: 20px; }}
        .test-frame {{ 
            position: relative; 
            width: 800px; 
            height: 600px; 
            border: 2px solid #ccc;
        }}
        .overlay {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255, 0, 0, 0.3);
            pointer-events: none;
            z-index: 10;
        }}
        iframe {{
            width: 100%;
            height: 100%;
            border: none;
        }}
        .result {{ margin-top: 20px; padding: 15px; border-radius: 5px; }}
        .vulnerable {{ background: #ffebee; border: 1px solid #ef5350; }}
        .protected {{ background: #e8f5e9; border: 1px solid #66bb6a; }}
    </style>
</head>
<body>
    <h1>Clickjacking Test</h1>
    <p>Target: <code>{target_url}</code></p>
    <p>If you can see the target website inside the red overlay below, it's vulnerable to clickjacking.</p>
    
    <div class="test-frame">
        <iframe src="{target_url}"></iframe>
        <div class="overlay" onclick="alert('Clickjacking successful!')"></div>
    </div>
    
    <div class="result" id="result">
        Testing...
    </div>
    
    <script>
        // Try to detect if iframe loaded
        const iframe = document.querySelector('iframe');
        const resultDiv = document.getElementById('result');
        
        iframe.onload = function() {{
            try {{
                const doc = iframe.contentDocument || iframe.contentWindow.document;
                resultDiv.innerHTML = '<div class="vulnerable"><strong>VULNERABLE:</strong> Page loaded in iframe. Clickjacking possible!</div>';
                resultDiv.className = 'result vulnerable';
            }} catch (e) {{
                resultDiv.innerHTML = '<div class="protected"><strong>PROTECTED:</strong> Cannot access iframe content (X-Frame-Options or CSP blocking).</div>';
                resultDiv.className = 'result protected';
            }}
        }};
        
        iframe.onerror = function() {{
            resultDiv.innerHTML = '<div class="protected"><strong>PROTECTED:</strong> Failed to load in iframe (likely blocked by X-Frame-Options or CSP).</div>';
            resultDiv.className = 'result protected';
        }};
    </script>
</body>
</html>
"""
    
    async def close(self):
        await self.client.aclose()


class SecurityScanner:
    """Main scanner orchestrating all checks"""
    
    def __init__(self):
        self.sslabs = SSLabsAPI()
        self.dns_checker = DNSSecurityChecker()
        self.cors_checker = CORSChecker()
        self.clickjacking_checker = ClickjackingChecker()
    
    async def run_full_scan(self, domain: str) -> Dict[str, Any]:
        """Run all security checks"""
        results = {
            "domain": domain,
            "scanned_at": datetime.utcnow().isoformat(),
        }
        
        # Run checks in parallel where possible
        tasks = [
            self._run_sslabs(domain),
            self._run_dns_checks(domain),
            self._run_cors_checks(domain),
            self._run_clickjacking_check(domain),
        ]
        
        sslabs_result, dns_result, cors_result, clickjacking_result = await asyncio.gather(
            *tasks, return_exceptions=True
        )
        
        results["sslabs"] = sslabs_result if not isinstance(sslabs_result, Exception) else {"error": str(sslabs_result)}
        results["dns_security"] = dns_result if not isinstance(dns_result, Exception) else {"error": str(dns_result)}
        results["cors"] = cors_result if not isinstance(cors_result, Exception) else {"error": str(cors_result)}
        results["clickjacking"] = clickjacking_result if not isinstance(clickjacking_result, Exception) else {"error": str(clickjacking_result)}
        
        # Calculate overall risk score
        results["risk_score"] = self._calculate_risk_score(results)
        
        return results
    
    async def _run_sslabs(self, domain: str) -> Dict[str, Any]:
        """Run SSL Labs analysis"""
        try:
            result = await self.sslabs.wait_for_completion(domain)
            return {
                "grade": self.sslabs.get_grade(result),
                "vulnerabilities": self.sslabs.get_vulnerabilities(result),
                "protocols": self.sslabs.get_protocol_support(result),
                "cipher_strength": self.sslabs.get_cipher_strength(result),
                "raw": result,
            }
        except Exception as e:
            return {"error": str(e)}
    
    async def _run_dns_checks(self, domain: str) -> Dict[str, Any]:
        return await self.dns_checker.check_all(domain)
    
    async def _run_cors_checks(self, domain: str) -> Dict[str, Any]:
        return await self.cors_checker.check_cors(f"https://{domain}")
    
    async def _run_clickjacking_check(self, domain: str) -> Dict[str, Any]:
        return await self.clickjacking_checker.check(f"https://{domain}")
    
    def _calculate_risk_score(self, results: Dict[str, Any]) -> int:
        """Calculate overall risk score (0-100, higher = more risk)"""
        risk = 0
        
        # SSL Labs grade
        sslabs = results.get("sslabs", {})
        if "grade" in sslabs:
            grade_map = {"A+": 0, "A": 5, "A-": 10, "B": 20, "C": 30, "D": 40, "E": 50, "F": 60}
            risk += grade_map.get(sslabs["grade"], 50)
        
        # DNS Security
        dns = results.get("dns_security", {})
        dns_score = dns.get("overall_score", 0)
        risk += (100 - dns_score) * 0.3
        
        # CORS
        cors = results.get("cors", {})
        if cors.get("wildcard_origin"):
            risk += 20
        if cors.get("allows_credentials") and cors.get("wildcard_origin"):
            risk += 30
        
        # Clickjacking
        cj = results.get("clickjacking", {})
        if cj.get("vulnerable"):
            risk += 15
        
        return min(int(risk), 100)
    
    async def close(self):
        await self.sslabs.close()
        await self.cors_checker.close()
        await self.clickjacking_checker.close()