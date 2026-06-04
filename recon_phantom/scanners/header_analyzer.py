"""HTTP Security Header Analyzer module.

Checks for the presence and correctness of HTTP security headers,
grades each header's configuration, and detects common misconfigurations.
"""

from typing import Any, Optional

import httpx

from recon_phantom.scanners.base import BaseScanner


# Security header definitions with expected values and grading criteria
SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "strict-transport-security": {
        "name": "HTTP Strict Transport Security (HSTS)",
        "required": True,
        "severity_missing": "high",
        "description": "Forces browsers to use HTTPS for all future requests to the domain.",
        "best_practice": "max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "name": "Content Security Policy (CSP)",
        "required": True,
        "severity_missing": "high",
        "description": "Prevents XSS, clickjacking, and other code injection attacks.",
        "best_practice": "default-src 'self'; script-src 'self'; style-src 'self'",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "required": True,
        "severity_missing": "medium",
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "best_practice": "DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "required": True,
        "severity_missing": "medium",
        "description": "Prevents MIME-type sniffing attacks.",
        "best_practice": "nosniff",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "required": True,
        "severity_missing": "low",
        "description": "Controls how much referrer information is sent with requests.",
        "best_practice": "strict-origin-when-cross-origin or no-referrer",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "required": False,
        "severity_missing": "low",
        "description": "Controls which browser features and APIs can be used.",
        "best_practice": "geolocation=(), microphone=(), camera=()",
    },
    "access-control-allow-origin": {
        "name": "CORS (Access-Control-Allow-Origin)",
        "required": False,
        "severity_missing": "info",
        "description": "Controls cross-origin resource sharing policy.",
        "best_practice": "Specific origins only, never wildcard '*' for credentialed requests",
    },
}

# HSTS configuration checks
HSTS_MIN_MAX_AGE = 31536000  # 1 year in seconds
HSTS_RECOMMENDED_MAX_AGE = 63072000  # 2 years in seconds

# Valid X-Frame-Options values
VALID_XFO_VALUES = {"deny", "sameorigin"}

# Secure Referrer-Policy values (ordered from most to least restrictive)
SECURE_REFERRER_POLICIES = {
    "no-referrer",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "same-origin",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
}

# Insecure CSP directives
INSECURE_CSP_DIRECTIVES = [
    "unsafe-inline",
    "unsafe-eval",
    "data:",
    "*",
]


class HeaderAnalyzer(BaseScanner):
    """Analyzes HTTP security headers for misconfigurations and missing protections.

    Checks response headers against security best practices, grades each header,
    and provides actionable recommendations for hardening.
    """

    @property
    def module_name(self) -> str:
        return "header_analyzer"

    async def run(self) -> list[dict[str, Any]]:
        """Execute the header analysis scan.

        Returns:
            List of findings for missing or misconfigured security headers.
        """
        results: list[dict[str, Any]] = []
        base_url = self.get_base_url("https")

        await self.emit_event("header_scan_started", {"url": base_url})

        # Fetch the target with both HTTP and HTTPS
        responses = await self._fetch_target_headers(base_url)

        if not responses:
            results.append(self.build_result(
                title="Target Unreachable",
                description=f"Could not connect to {base_url} for header analysis.",
                severity="info",
                host=self.target,
                protocol="https",
            ))
            return results

        for scheme, response in responses.items():
            if response is None:
                continue

            headers = {k.lower(): v for k, v in response.headers.items()}
            url_used = f"{scheme}://{self.target}"

            # Check each security header
            results.extend(self._check_hsts(headers, url_used, scheme))
            results.extend(self._check_csp(headers, url_used))
            results.extend(self._check_xfo(headers, url_used))
            results.extend(self._check_xcto(headers, url_used))
            results.extend(self._check_referrer_policy(headers, url_used))
            results.extend(self._check_permissions_policy(headers, url_used))
            results.extend(self._check_cors(headers, url_used))
            results.extend(self._check_deprecated_headers(headers, url_used))
            results.extend(self._check_info_disclosure(headers, url_used))

        # Calculate overall grade
        grade = self._calculate_grade(results)
        results.append(self.build_result(
            title=f"Security Header Grade: {grade}",
            description=f"Overall security header assessment grade: {grade}",
            severity="info",
            host=self.target,
            data={"grade": grade, "total_findings": len(results)},
            confidence=0.95,
        ))

        await self.emit_event("header_scan_completed", {"findings": len(results)})
        return results

    async def _fetch_target_headers(
        self, base_url: str
    ) -> dict[str, Optional[httpx.Response]]:
        """Fetch headers from both HTTP and HTTPS endpoints.

        Returns:
            Dictionary mapping scheme to response object.
        """
        responses: dict[str, Optional[httpx.Response]] = {}

        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.target}"
            response = await self.make_request(
                url, follow_redirects=False, timeout=self.timeout
            )
            responses[scheme] = response

        return responses

    def _check_hsts(
        self, headers: dict[str, str], url: str, scheme: str
    ) -> list[dict[str, Any]]:
        """Check HSTS header presence and configuration."""
        results: list[dict[str, Any]] = []
        hsts_value = headers.get("strict-transport-security", "")

        if not hsts_value:
            results.append(self.build_result(
                title="Missing HSTS Header",
                description=(
                    "The Strict-Transport-Security header is not set. "
                    "This allows man-in-the-middle attacks via protocol downgrade."
                ),
                severity="high",
                host=self.target,
                path="/",
                protocol=scheme,
                data={"header": "Strict-Transport-Security", "status": "missing"},
                confidence=1.0,
            ))
            return results

        # Parse max-age
        max_age = self._parse_hsts_max_age(hsts_value)
        if max_age is not None:
            if max_age < HSTS_MIN_MAX_AGE:
                results.append(self.build_result(
                    title="HSTS max-age Too Short",
                    description=(
                        f"HSTS max-age is {max_age} seconds "
                        f"(recommended minimum: {HSTS_MIN_MAX_AGE}). "
                        "Short max-age values reduce protection effectiveness."
                    ),
                    severity="medium",
                    evidence=f"strict-transport-security: {hsts_value}",
                    host=self.target,
                    data={"max_age": max_age, "recommended": HSTS_MIN_MAX_AGE},
                    confidence=0.95,
                ))
            elif max_age == 0:
                results.append(self.build_result(
                    title="HSTS Effectively Disabled (max-age=0)",
                    description="HSTS max-age is set to 0, which disables the protection.",
                    severity="high",
                    evidence=f"strict-transport-security: {hsts_value}",
                    host=self.target,
                    confidence=1.0,
                ))

        # Check for includeSubDomains
        if "includesubdomains" not in hsts_value.lower():
            results.append(self.build_result(
                title="HSTS Missing includeSubDomains",
                description=(
                    "HSTS does not include the includeSubDomains directive. "
                    "Subdomains are not protected from protocol downgrade attacks."
                ),
                severity="low",
                evidence=f"strict-transport-security: {hsts_value}",
                host=self.target,
                confidence=0.9,
            ))

        # Check for preload
        if "preload" not in hsts_value.lower():
            results.append(self.build_result(
                title="HSTS Missing preload Directive",
                description=(
                    "HSTS does not include the preload directive. "
                    "The domain is not eligible for browser preload lists."
                ),
                severity="info",
                evidence=f"strict-transport-security: {hsts_value}",
                host=self.target,
                confidence=0.9,
            ))

        return results

    def _parse_hsts_max_age(self, value: str) -> Optional[int]:
        """Extract max-age value from HSTS header."""
        for part in value.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age="):
                try:
                    return int(part.split("=", 1)[1].strip())
                except (ValueError, IndexError):
                    return None
        return None

    def _check_csp(self, headers: dict[str, str], url: str) -> list[dict[str, Any]]:
        """Check Content-Security-Policy header."""
        results: list[dict[str, Any]] = []
        csp_value = headers.get("content-security-policy", "")

        if not csp_value:
            # Check for report-only variant
            csp_ro = headers.get("content-security-policy-report-only", "")
            severity = "high" if not csp_ro else "medium"
            desc = "Content-Security-Policy header is missing."
            if csp_ro:
                desc += " A report-only policy exists but does not enforce restrictions."

            results.append(self.build_result(
                title="Missing Content-Security-Policy",
                description=desc,
                severity=severity,
                host=self.target,
                data={"header": "Content-Security-Policy", "report_only": bool(csp_ro)},
                confidence=1.0,
            ))
            return results

        # Check for dangerous directives
        for directive in INSECURE_CSP_DIRECTIVES:
            if directive in csp_value:
                sev = "high" if directive in ("unsafe-eval", "*") else "medium"
                results.append(self.build_result(
                    title=f"CSP Contains Insecure Directive: {directive}",
                    description=(
                        f"The CSP includes '{directive}' which weakens "
                        "the security policy and may allow XSS attacks."
                    ),
                    severity=sev,
                    evidence=f"content-security-policy: {csp_value[:200]}",
                    host=self.target,
                    data={"insecure_directive": directive},
                    confidence=0.9,
                ))

        # Check if default-src is set
        if "default-src" not in csp_value:
            results.append(self.build_result(
                title="CSP Missing default-src Directive",
                description=(
                    "The CSP does not define a default-src fallback. "
                    "Resource types without explicit directives are unrestricted."
                ),
                severity="medium",
                evidence=f"content-security-policy: {csp_value[:200]}",
                host=self.target,
                confidence=0.85,
            ))

        return results

    def _check_xfo(self, headers: dict[str, str], url: str) -> list[dict[str, Any]]:
        """Check X-Frame-Options header."""
        results: list[dict[str, Any]] = []
        xfo_value = headers.get("x-frame-options", "").lower().strip()

        if not xfo_value:
            results.append(self.build_result(
                title="Missing X-Frame-Options Header",
                description=(
                    "X-Frame-Options is not set. The page may be vulnerable "
                    "to clickjacking attacks via iframe embedding."
                ),
                severity="medium",
                host=self.target,
                data={"header": "X-Frame-Options", "status": "missing"},
                confidence=1.0,
            ))
        elif xfo_value not in VALID_XFO_VALUES:
            if xfo_value.startswith("allow-from"):
                results.append(self.build_result(
                    title="X-Frame-Options Uses Deprecated ALLOW-FROM",
                    description=(
                        "ALLOW-FROM is deprecated and not supported by modern browsers. "
                        "Use CSP frame-ancestors directive instead."
                    ),
                    severity="medium",
                    evidence=f"x-frame-options: {xfo_value}",
                    host=self.target,
                    confidence=0.95,
                ))
            else:
                results.append(self.build_result(
                    title="Invalid X-Frame-Options Value",
                    description=f"X-Frame-Options has an invalid value: '{xfo_value}'.",
                    severity="medium",
                    evidence=f"x-frame-options: {xfo_value}",
                    host=self.target,
                    confidence=0.9,
                ))

        return results

    def _check_xcto(self, headers: dict[str, str], url: str) -> list[dict[str, Any]]:
        """Check X-Content-Type-Options header."""
        results: list[dict[str, Any]] = []
        xcto_value = headers.get("x-content-type-options", "").lower().strip()

        if not xcto_value:
            results.append(self.build_result(
                title="Missing X-Content-Type-Options Header",
                description=(
                    "X-Content-Type-Options is not set. The browser may "
                    "perform MIME-type sniffing, leading to security issues."
                ),
                severity="medium",
                host=self.target,
                data={"header": "X-Content-Type-Options", "status": "missing"},
                confidence=1.0,
            ))
        elif xcto_value != "nosniff":
            results.append(self.build_result(
                title="Invalid X-Content-Type-Options Value",
                description=f"Expected 'nosniff' but got '{xcto_value}'.",
                severity="medium",
                evidence=f"x-content-type-options: {xcto_value}",
                host=self.target,
                confidence=0.95,
            ))

        return results

    def _check_referrer_policy(
        self, headers: dict[str, str], url: str
    ) -> list[dict[str, Any]]:
        """Check Referrer-Policy header."""
        results: list[dict[str, Any]] = []
        rp_value = headers.get("referrer-policy", "").lower().strip()

        if not rp_value:
            results.append(self.build_result(
                title="Missing Referrer-Policy Header",
                description=(
                    "Referrer-Policy is not set. The full URL including "
                    "sensitive query parameters may be leaked to third parties."
                ),
                severity="low",
                host=self.target,
                data={"header": "Referrer-Policy", "status": "missing"},
                confidence=1.0,
            ))
        elif rp_value == "unsafe-url":
            results.append(self.build_result(
                title="Insecure Referrer-Policy: unsafe-url",
                description=(
                    "Referrer-Policy is set to 'unsafe-url' which sends the full "
                    "URL as referrer for all requests, potentially leaking sensitive data."
                ),
                severity="medium",
                evidence=f"referrer-policy: {rp_value}",
                host=self.target,
                confidence=1.0,
            ))
        elif rp_value not in SECURE_REFERRER_POLICIES:
            results.append(self.build_result(
                title=f"Non-standard Referrer-Policy: {rp_value}",
                description=f"Referrer-Policy has an unrecognized value: '{rp_value}'.",
                severity="low",
                evidence=f"referrer-policy: {rp_value}",
                host=self.target,
                confidence=0.8,
            ))

        return results

    def _check_permissions_policy(
        self, headers: dict[str, str], url: str
    ) -> list[dict[str, Any]]:
        """Check Permissions-Policy header."""
        results: list[dict[str, Any]] = []
        pp_value = headers.get("permissions-policy", "")
        # Also check deprecated Feature-Policy
        fp_value = headers.get("feature-policy", "")

        if not pp_value and not fp_value:
            results.append(self.build_result(
                title="Missing Permissions-Policy Header",
                description=(
                    "Permissions-Policy is not set. Browser features like "
                    "camera, microphone, and geolocation are not restricted."
                ),
                severity="low",
                host=self.target,
                data={"header": "Permissions-Policy", "status": "missing"},
                confidence=1.0,
            ))
        elif fp_value and not pp_value:
            results.append(self.build_result(
                title="Deprecated Feature-Policy Header Used",
                description=(
                    "The site uses the deprecated Feature-Policy header. "
                    "Migrate to the Permissions-Policy header."
                ),
                severity="info",
                evidence=f"feature-policy: {fp_value[:200]}",
                host=self.target,
                confidence=0.95,
            ))

        return results

    def _check_cors(self, headers: dict[str, str], url: str) -> list[dict[str, Any]]:
        """Check CORS configuration for overly permissive settings."""
        results: list[dict[str, Any]] = []
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()

        if acao == "*":
            if acac == "true":
                results.append(self.build_result(
                    title="CORS Wildcard with Credentials Allowed",
                    description=(
                        "CORS is configured with Access-Control-Allow-Origin: * and "
                        "Access-Control-Allow-Credentials: true. This is a severe "
                        "misconfiguration that may allow credential theft."
                    ),
                    severity="critical",
                    evidence=f"access-control-allow-origin: {acao}",
                    host=self.target,
                    confidence=1.0,
                ))
            else:
                results.append(self.build_result(
                    title="CORS Wildcard Origin Allowed",
                    description=(
                        "CORS allows any origin (*). While not always dangerous, "
                        "it may expose API data to unauthorized origins."
                    ),
                    severity="low",
                    evidence=f"access-control-allow-origin: {acao}",
                    host=self.target,
                    confidence=0.85,
                ))
        elif acao == "null":
            results.append(self.build_result(
                title="CORS Allows Null Origin",
                description=(
                    "CORS allows the 'null' origin, which can be exploited "
                    "via sandboxed iframes to bypass same-origin restrictions."
                ),
                severity="medium",
                evidence=f"access-control-allow-origin: {acao}",
                host=self.target,
                confidence=0.9,
            ))

        return results

    def _check_deprecated_headers(
        self, headers: dict[str, str], url: str
    ) -> list[dict[str, Any]]:
        """Check for deprecated or unnecessary security headers."""
        results: list[dict[str, Any]] = []

        # X-XSS-Protection is deprecated and can cause issues
        xxp = headers.get("x-xss-protection", "")
        if xxp and xxp.strip() == "1; mode=block":
            results.append(self.build_result(
                title="Deprecated X-XSS-Protection Header Present",
                description=(
                    "X-XSS-Protection is deprecated and can introduce "
                    "vulnerabilities in older browsers. Use CSP instead."
                ),
                severity="info",
                evidence=f"x-xss-protection: {xxp}",
                host=self.target,
                confidence=0.8,
            ))

        return results

    def _check_info_disclosure(
        self, headers: dict[str, str], url: str
    ) -> list[dict[str, Any]]:
        """Check for information disclosure via headers."""
        results: list[dict[str, Any]] = []

        # Server header disclosure
        server = headers.get("server", "")
        if server and "/" in server:
            results.append(self.build_result(
                title="Server Version Disclosure",
                description=(
                    f"The Server header discloses version information: '{server}'. "
                    "This helps attackers identify specific vulnerabilities."
                ),
                severity="low",
                evidence=f"server: {server}",
                host=self.target,
                confidence=0.9,
            ))

        # X-Powered-By disclosure
        xpb = headers.get("x-powered-by", "")
        if xpb:
            results.append(self.build_result(
                title="X-Powered-By Header Disclosure",
                description=(
                    f"X-Powered-By header reveals technology stack: '{xpb}'. "
                    "Remove this header to reduce information leakage."
                ),
                severity="low",
                evidence=f"x-powered-by: {xpb}",
                host=self.target,
                confidence=0.95,
            ))

        # X-AspNet-Version
        aspnet = headers.get("x-aspnet-version", "")
        if aspnet:
            results.append(self.build_result(
                title="ASP.NET Version Disclosure",
                description=f"X-AspNet-Version header reveals: '{aspnet}'.",
                severity="low",
                evidence=f"x-aspnet-version: {aspnet}",
                host=self.target,
                confidence=0.95,
            ))

        return results

    def _calculate_grade(self, results: list[dict[str, Any]]) -> str:
        """Calculate an overall letter grade based on findings.

        Returns:
            Letter grade from A+ to F.
        """
        severity_scores = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 0,
        }

        total_penalty = sum(
            severity_scores.get(r.get("severity", "info"), 0)
            for r in results
            if r.get("severity") != "info"
        )

        if total_penalty == 0:
            return "A+"
        elif total_penalty <= 5:
            return "A"
        elif total_penalty <= 15:
            return "B"
        elif total_penalty <= 30:
            return "C"
        elif total_penalty <= 50:
            return "D"
        else:
            return "F"
