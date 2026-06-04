"""JavaScript Analyzer module.

Discovers and analyzes JavaScript files to extract sensitive information
including API endpoints, hardcoded secrets, internal URLs, and configuration
objects that may reveal application internals.
"""

import asyncio
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse


from recon_phantom.scanners.base import BaseScanner


# Regex patterns for extracting API endpoints from JavaScript
API_ENDPOINT_PATTERNS: list[re.Pattern] = [
    re.compile(r'''fetch\s*\(\s*['"](\/api\/[^'"]+)['"]''', re.IGNORECASE),
    re.compile(r'''fetch\s*\(\s*['"]([^'"]*\/v[0-9]+\/[^'"]+)['"]''', re.IGNORECASE),
    re.compile(r'''axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"](\/[^'"]+)['"]''', re.IGNORECASE),
    re.compile(r'''(?:url|endpoint|api_url|apiUrl|baseUrl|base_url)\s*[:=]\s*['"]([^'"]{5,})['"]''', re.IGNORECASE),
    re.compile(r'''\.(?:get|post|put|delete|patch)\s*\(\s*['"](\/?api\/[^'"]+)['"]''', re.IGNORECASE),
    re.compile(r'''XMLHttpRequest.*?open\s*\(\s*['"]\w+['"]\s*,\s*['"]([^'"]+)['"]''', re.IGNORECASE | re.DOTALL),
    re.compile(r'''(?:href|src|action)\s*[:=]\s*['"](\/?api\/[^'"]+)['"]''', re.IGNORECASE),
    re.compile(r'''['"](\/?(?:api|graphql|rest|v[0-9]+)\/[a-zA-Z0-9/_\-{}]+)['"]''', re.IGNORECASE),
]

# Regex patterns for detecting hardcoded secrets
SECRET_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'''(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''),
        "severity": "critical",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r'''(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?''', re.IGNORECASE),
        "severity": "critical",
    },
    {
        "name": "Generic API Key",
        "pattern": re.compile(r'''(?:api[_-]?key|apikey)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]''', re.IGNORECASE),
        "severity": "high",
    },
    {
        "name": "Generic Secret/Token",
        "pattern": re.compile(r'''(?:secret|token|auth_token|access_token)\s*[:=]\s*['"]([a-zA-Z0-9_\-./+=]{16,})['"]''', re.IGNORECASE),
        "severity": "high",
    },
    {
        "name": "Google API Key",
        "pattern": re.compile(r'''AIza[0-9A-Za-z\-_]{35}'''),
        "severity": "high",
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r'''(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'''),
        "severity": "critical",
    },
    {
        "name": "Stripe API Key",
        "pattern": re.compile(r'''(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}'''),
        "severity": "critical",
    },
    {
        "name": "Slack Token",
        "pattern": re.compile(r'''xox[baprs]-[0-9]{10,}-[A-Za-z0-9\-]+'''),
        "severity": "critical",
    },
    {
        "name": "Private Key",
        "pattern": re.compile(r'''-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'''),
        "severity": "critical",
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(r'''eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-+/=]{10,}'''),
        "severity": "high",
    },
    {
        "name": "Twilio API Key",
        "pattern": re.compile(r'''SK[0-9a-fA-F]{32}'''),
        "severity": "high",
    },
    {
        "name": "SendGrid API Key",
        "pattern": re.compile(r'''SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}'''),
        "severity": "critical",
    },
    {
        "name": "Heroku API Key",
        "pattern": re.compile(r'''(?:heroku.*?api[_-]?key)\s*[:=]\s*['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?''', re.IGNORECASE),
        "severity": "high",
    },
    {
        "name": "Firebase Config",
        "pattern": re.compile(r'''(?:apiKey|authDomain|databaseURL|storageBucket|messagingSenderId|appId)\s*:\s*['"]([^'"]+)['"]''', re.IGNORECASE),
        "severity": "medium",
    },
    {
        "name": "Database Connection String",
        "pattern": re.compile(r'''(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"<>]{10,}''', re.IGNORECASE),
        "severity": "critical",
    },
    {
        "name": "Password/Credential Assignment",
        "pattern": re.compile(r'''(?:password|passwd|pwd|credentials?)\s*[:=]\s*['"]([^'"]{4,})['"]''', re.IGNORECASE),
        "severity": "high",
    },
]

# Patterns for internal/interesting URLs
INTERNAL_URL_PATTERNS: list[re.Pattern] = [
    re.compile(r'''['"]((https?:\/\/)?(?:\w+\.)?(?:internal|staging|dev|test|local|localhost|corp|intranet)[^'"]*?)['"]''', re.IGNORECASE),
    re.compile(r'''['"]((https?:\/\/)?(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^'"]*?)['"]'''),
    re.compile(r'''['"]((https?:\/\/)?[a-zA-Z0-9\-]+\.(?:local|internal|corp|intranet|lan)(?::\d+)?[^'"]*?)['"]''', re.IGNORECASE),
    re.compile(r'''['"]((https?:\/\/)?localhost(?::\d+)?[^'"]*?)['"]''', re.IGNORECASE),
]

# Config object patterns
CONFIG_PATTERNS: list[re.Pattern] = [
    re.compile(r'''(?:window|global|self)\.__(?:CONFIG|INITIAL_STATE|ENV|DATA|APP)__\s*=\s*(\{[^;]{20,}?\});''', re.DOTALL),
    re.compile(r'''(?:var|let|const)\s+(?:config|CONFIG|settings|appConfig|APP_CONFIG)\s*=\s*(\{[^;]{20,}?\});''', re.DOTALL),
    re.compile(r'''(?:process\.env|import\.meta\.env)\s*[:=]\s*(\{[^}]+\})''', re.DOTALL),
]

# Script tag extraction from HTML
SCRIPT_SRC_PATTERN = re.compile(
    r'''<script[^>]+src\s*=\s*['"]([^'"]+\.js[^'"]*)['"]''', re.IGNORECASE
)


class JSAnalyzer(BaseScanner):
    """Analyzes JavaScript files for sensitive information leakage.

    Discovers JavaScript files from HTML pages, downloads them, and extracts
    API endpoints, hardcoded secrets, internal URLs, and configuration objects
    that may reveal application internals.
    """

    @property
    def module_name(self) -> str:
        return "js_analyzer"

    async def run(self) -> list[dict[str, Any]]:
        """Execute the JavaScript analysis scan.

        Returns:
            List of findings from JavaScript analysis.
        """
        results: list[dict[str, Any]] = []
        base_url = self.get_base_url("https")

        await self.emit_event("js_analysis_started", {"url": base_url})

        # Phase 1: Discover JavaScript files from HTML
        js_urls = await self._discover_js_files(base_url)

        if not js_urls:
            results.append(self.build_result(
                title="No JavaScript Files Discovered",
                description=f"No JavaScript files found on {base_url}.",
                severity="info",
                host=self.target,
                confidence=0.7,
            ))
            await self.emit_event("js_analysis_completed", {"js_files": 0})
            return results

        await self.emit_event("js_files_discovered", {"count": len(js_urls)})

        # Phase 2: Fetch and analyze each JavaScript file
        semaphore = self.get_semaphore()

        async def analyze_js(url: str) -> list[dict[str, Any]]:
            async with semaphore:
                return await self._analyze_js_file(url, base_url)

        # Limit to max 50 JS files to avoid excessive scanning
        max_js_files = self.config.get("max_js_files", 50)
        js_urls_limited = list(js_urls)[:max_js_files]

        tasks = [analyze_js(url) for url in js_urls_limited]
        all_file_results = await asyncio.gather(*tasks, return_exceptions=True)

        for file_results in all_file_results:
            if isinstance(file_results, list):
                results.extend(file_results)

        # Summary
        secrets_found = sum(1 for r in results if "Secret" in r.get("title", "") or "Key" in r.get("title", ""))
        endpoints_found = sum(1 for r in results if "API Endpoint" in r.get("title", ""))
        internal_urls = sum(1 for r in results if "Internal URL" in r.get("title", ""))

        results.append(self.build_result(
            title="JavaScript Analysis Summary",
            description=(
                f"Analyzed {len(js_urls_limited)} JavaScript files. "
                f"Found: {secrets_found} potential secrets, "
                f"{endpoints_found} API endpoints, "
                f"{internal_urls} internal URLs."
            ),
            severity="info",
            host=self.target,
            data={
                "js_files_analyzed": len(js_urls_limited),
                "js_files_total": len(js_urls),
                "secrets_found": secrets_found,
                "endpoints_found": endpoints_found,
                "internal_urls": internal_urls,
            },
            confidence=0.95,
        ))

        await self.emit_event("js_analysis_completed", {
            "js_files": len(js_urls_limited),
            "findings": len(results),
        })
        return results

    async def _discover_js_files(self, base_url: str) -> set[str]:
        """Discover JavaScript file URLs from HTML pages.

        Returns:
            Set of absolute JavaScript file URLs.
        """
        js_urls: set[str] = set()

        # Fetch the main page
        response = await self.make_request(base_url)
        if response is None or response.status_code != 200:
            return js_urls

        html = response.text or ""
        js_urls.update(self._extract_js_urls(html, base_url))

        # Also check common paths for additional JS discovery
        additional_pages = ["/", "/login", "/app", "/dashboard"]
        for page in additional_pages:
            page_url = f"{base_url}{page}"
            if page_url == base_url:
                continue
            resp = await self.make_request(page_url)
            if resp and resp.status_code == 200 and resp.text:
                js_urls.update(self._extract_js_urls(resp.text, base_url))

        return js_urls

    def _extract_js_urls(self, html: str, base_url: str) -> set[str]:
        """Extract JavaScript URLs from HTML content.

        Returns:
            Set of absolute JS file URLs.
        """
        js_urls: set[str] = set()

        matches = SCRIPT_SRC_PATTERN.findall(html)
        for src in matches:
            # Skip inline data URIs and analytics
            if src.startswith("data:") or "google-analytics" in src:
                continue

            # Convert relative URLs to absolute
            absolute_url = self._resolve_url(src, base_url)
            if absolute_url:
                js_urls.add(absolute_url)

        return js_urls

    def _resolve_url(self, url: str, base_url: str) -> Optional[str]:
        """Resolve a potentially relative URL to absolute.

        Returns:
            Absolute URL string or None if invalid.
        """
        if url.startswith("//"):
            return f"https:{url}"
        elif url.startswith("http://") or url.startswith("https://"):
            return url
        elif url.startswith("/"):
            parsed = urlparse(base_url)
            return f"{parsed.scheme}://{parsed.netloc}{url}"
        else:
            return urljoin(base_url + "/", url)

    async def _analyze_js_file(
        self, js_url: str, base_url: str
    ) -> list[dict[str, Any]]:
        """Fetch and analyze a single JavaScript file.

        Returns:
            List of findings from this JS file.
        """
        results: list[dict[str, Any]] = []

        response = await self.make_request(js_url)
        if response is None or response.status_code != 200:
            return results

        content = response.text or ""
        if not content or len(content) < 10:
            return results

        # Limit analysis to reasonable file sizes (5MB max)
        max_size = 5 * 1024 * 1024
        if len(content) > max_size:
            content = content[:max_size]

        js_filename = urlparse(js_url).path.split("/")[-1] or "unknown.js"

        # Extract API endpoints
        endpoints = self._extract_api_endpoints(content)
        if endpoints:
            results.append(self.build_result(
                title=f"API Endpoints Found in {js_filename}",
                description=(
                    f"Discovered {len(endpoints)} API endpoint(s) in JavaScript file. "
                    "These endpoints may expose internal API surface."
                ),
                severity="low",
                evidence="\n".join(endpoints[:20]),
                host=self.target,
                path=urlparse(js_url).path,
                data={
                    "source_file": js_url,
                    "endpoints": endpoints[:50],
                    "count": len(endpoints),
                },
                confidence=0.8,
            ))

        # Extract secrets
        secrets = self._extract_secrets(content)
        for secret in secrets:
            results.append(self.build_result(
                title=f"{secret['name']} Found in {js_filename}",
                description=(
                    f"Potential {secret['name']} found in JavaScript file. "
                    "Hardcoded secrets in client-side code are accessible to anyone."
                ),
                severity=secret["severity"],
                evidence=f"Match: {secret['match'][:100]}{'...' if len(secret['match']) > 100 else ''}",
                host=self.target,
                path=urlparse(js_url).path,
                data={
                    "source_file": js_url,
                    "secret_type": secret["name"],
                    "context": secret.get("context", ""),
                },
                confidence=0.75,
            ))

        # Extract internal URLs
        internal_urls = self._extract_internal_urls(content)
        if internal_urls:
            results.append(self.build_result(
                title=f"Internal URLs Found in {js_filename}",
                description=(
                    f"Found {len(internal_urls)} internal/private URL(s) in JavaScript. "
                    "These may reveal internal infrastructure."
                ),
                severity="medium",
                evidence="\n".join(internal_urls[:15]),
                host=self.target,
                path=urlparse(js_url).path,
                data={
                    "source_file": js_url,
                    "internal_urls": internal_urls[:30],
                    "count": len(internal_urls),
                },
                confidence=0.7,
            ))

        # Extract config objects
        configs = self._extract_config_objects(content)
        if configs:
            results.append(self.build_result(
                title=f"Configuration Object Found in {js_filename}",
                description=(
                    f"Found {len(configs)} embedded configuration object(s) in JavaScript. "
                    "May contain environment details, feature flags, or sensitive settings."
                ),
                severity="medium",
                evidence="\n".join(c[:200] for c in configs[:3]),
                host=self.target,
                path=urlparse(js_url).path,
                data={
                    "source_file": js_url,
                    "config_count": len(configs),
                    "config_preview": [c[:500] for c in configs[:3]],
                },
                confidence=0.7,
            ))

        return results

    def _extract_api_endpoints(self, content: str) -> list[str]:
        """Extract API endpoint paths from JavaScript content.

        Returns:
            Deduplicated list of API endpoint strings.
        """
        endpoints: set[str] = set()

        for pattern in API_ENDPOINT_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                endpoint = match.strip()
                # Filter out obvious non-endpoints
                if self._is_valid_endpoint(endpoint):
                    endpoints.add(endpoint)

        return sorted(endpoints)

    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Check if a string looks like a valid API endpoint."""
        if len(endpoint) < 3 or len(endpoint) > 500:
            return False

        # Skip common static assets
        static_extensions = (
            ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot",
        )
        if any(endpoint.lower().endswith(ext) for ext in static_extensions):
            return False

        # Skip common framework/library paths
        skip_patterns = (
            "node_modules", "webpack", "polyfill",
            "chunk", "vendor", "manifest",
        )
        if any(p in endpoint.lower() for p in skip_patterns):
            return False

        return True

    def _extract_secrets(self, content: str) -> list[dict[str, Any]]:
        """Extract potential secrets from JavaScript content.

        Returns:
            List of dictionaries with secret details.
        """
        secrets: list[dict[str, Any]] = []
        seen_matches: set[str] = set()

        for secret_def in SECRET_PATTERNS:
            matches = secret_def["pattern"].finditer(content)
            for match in matches:
                match_text = match.group(0)

                # Skip duplicates
                if match_text in seen_matches:
                    continue
                seen_matches.add(match_text)

                # Skip common false positives
                if self._is_secret_false_positive(match_text, secret_def["name"]):
                    continue

                # Get surrounding context (30 chars before and after)
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 30)
                context = content[start:end].replace("\n", " ").strip()

                secrets.append({
                    "name": secret_def["name"],
                    "severity": secret_def["severity"],
                    "match": match_text,
                    "context": context,
                })

        return secrets

    def _is_secret_false_positive(self, match: str, secret_type: str) -> bool:
        """Check if a secret match is likely a false positive."""
        # Skip placeholder/example values
        placeholder_indicators = [
            "example", "placeholder", "your_", "xxx", "CHANGE_ME",
            "INSERT_", "REPLACE", "TODO", "sample", "test123",
            "0000000", "abcdef", "123456",
        ]
        lower_match = match.lower()
        if any(p.lower() in lower_match for p in placeholder_indicators):
            return True

        # Skip very short generic matches for generic patterns
        if secret_type in ("Generic API Key", "Generic Secret/Token"):
            # Extract the actual value part
            for sep in ("=", ":", "'", '"'):
                if sep in match:
                    parts = match.split(sep)
                    value = parts[-1].strip("'\" ")
                    if len(value) < 16:
                        return True
                    break

        return False

    def _extract_internal_urls(self, content: str) -> list[str]:
        """Extract internal/private URLs from JavaScript content.

        Returns:
            Deduplicated list of internal URL strings.
        """
        internal_urls: set[str] = set()

        for pattern in INTERNAL_URL_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                url = match[0] if isinstance(match, tuple) else match
                url = url.strip()
                if len(url) > 5 and len(url) < 500:
                    # Verify it's not a common false positive
                    if not any(fp in url.lower() for fp in
                              ("localhost:0", "example.com", "test.local")):
                        internal_urls.add(url)

        return sorted(internal_urls)

    def _extract_config_objects(self, content: str) -> list[str]:
        """Extract configuration objects from JavaScript content.

        Returns:
            List of config object strings (truncated).
        """
        configs: list[str] = []

        for pattern in CONFIG_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                config_str = match.strip()
                if len(config_str) > 20:  # Skip trivial matches
                    configs.append(config_str[:1000])  # Truncate large configs

        return configs
