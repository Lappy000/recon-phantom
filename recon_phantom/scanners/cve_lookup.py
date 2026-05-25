"""CVE lookup scanner.

Queries the NVD/NIST API for known CVEs based on detected technologies
and their versions. Parses version numbers, matches against CPE strings,
and returns vulnerability information with severity ratings.
"""

import re
from typing import Any, Optional

import httpx

from recon_phantom.scanners.base import BaseScanner


# CPE mapping for common technologies (vendor:product)
TECH_TO_CPE: dict[str, tuple[str, str]] = {
    "Apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "IIS": ("microsoft", "internet_information_services"),
    "OpenSSH": ("openbsd", "openssh"),
    "PHP": ("php", "php"),
    "WordPress": ("wordpress", "wordpress"),
    "Drupal": ("drupal", "drupal"),
    "Joomla": ("joomla", "joomla\\!"),
    "jQuery": ("jquery", "jquery"),
    "React": ("facebook", "react"),
    "Angular": ("google", "angular"),
    "Vue.js": ("vuejs", "vue.js"),
    "Node.js": ("nodejs", "node.js"),
    "Express.js": ("expressjs", "express"),
    "Django": ("djangoproject", "django"),
    "Flask": ("palletsprojects", "flask"),
    "Ruby on Rails": ("rubyonrails", "rails"),
    "Laravel": ("laravel", "laravel"),
    "MySQL": ("mysql", "mysql"),
    "PostgreSQL": ("postgresql", "postgresql"),
    "Redis": ("redis", "redis"),
    "MongoDB": ("mongodb", "mongodb"),
    "Elasticsearch": ("elastic", "elasticsearch"),
    "Apache Tomcat": ("apache", "tomcat"),
    "Jenkins": ("jenkins", "jenkins"),
    "Grafana": ("grafana", "grafana"),
    "GitLab": ("gitlab", "gitlab"),
    "Next.js": ("vercel", "next.js"),
    "ASP.NET": ("microsoft", "asp.net"),
    "Varnish": ("varnish-cache", "varnish_cache"),
    "LiteSpeed": ("litespeedtech", "litespeed_web_server"),
    "OpenResty": ("openresty", "openresty"),
    "Caddy": ("caddyserver", "caddy"),
    "Spring": ("vmware", "spring_framework"),
    "Magento": ("magento", "magento"),
    "Shopify": ("shopify", "shopify"),
    "ProFTPD": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "Postfix": ("postfix", "postfix"),
    "Exim": ("exim", "exim"),
    "Dovecot": ("dovecot", "dovecot"),
    "MariaDB": ("mariadb", "mariadb"),
    "Sentry": ("sentry", "sentry"),
    "Kubernetes": ("kubernetes", "kubernetes"),
    "Docker": ("docker", "docker"),
}

# Known high-severity CVEs for quick matching (sample database)
KNOWN_CVES: dict[str, list[dict[str, Any]]] = {
    "apache:http_server": [
        {
            "cve_id": "CVE-2021-41773",
            "affected_versions": ["2.4.49"],
            "severity": "critical",
            "description": "Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49",
            "cvss": 9.8,
        },
        {
            "cve_id": "CVE-2021-42013",
            "affected_versions": ["2.4.49", "2.4.50"],
            "severity": "critical",
            "description": "Path traversal and RCE in Apache HTTP Server 2.4.49/2.4.50",
            "cvss": 9.8,
        },
        {
            "cve_id": "CVE-2023-25690",
            "affected_versions": ["2.4.0-2.4.55"],
            "severity": "high",
            "description": "HTTP request smuggling via mod_proxy in Apache HTTP Server",
            "cvss": 9.8,
        },
    ],
    "nginx:nginx": [
        {
            "cve_id": "CVE-2021-23017",
            "affected_versions": ["0.6.18-1.20.0"],
            "severity": "high",
            "description": "1-byte memory overwrite in nginx resolver",
            "cvss": 7.7,
        },
    ],
    "openbsd:openssh": [
        {
            "cve_id": "CVE-2024-6387",
            "affected_versions": ["8.5p1-9.7p1"],
            "severity": "critical",
            "description": "RegreSSHion: Remote code execution in OpenSSH server (race condition in signal handler)",
            "cvss": 8.1,
        },
        {
            "cve_id": "CVE-2023-38408",
            "affected_versions": ["5.5-9.3p1"],
            "severity": "high",
            "description": "Remote code execution via ssh-agent forwarding",
            "cvss": 9.8,
        },
    ],
    "php:php": [
        {
            "cve_id": "CVE-2024-4577",
            "affected_versions": ["8.1.0-8.1.28", "8.2.0-8.2.18", "8.3.0-8.3.5"],
            "severity": "critical",
            "description": "PHP CGI argument injection vulnerability",
            "cvss": 9.8,
        },
    ],
    "wordpress:wordpress": [
        {
            "cve_id": "CVE-2023-2982",
            "affected_versions": ["1.0-6.2.2"],
            "severity": "high",
            "description": "WordPress authentication bypass vulnerability",
            "cvss": 9.8,
        },
    ],
    "jquery:jquery": [
        {
            "cve_id": "CVE-2020-11022",
            "affected_versions": ["1.2-3.4.1"],
            "severity": "medium",
            "description": "jQuery XSS vulnerability in htmlPrefilter",
            "cvss": 6.1,
        },
        {
            "cve_id": "CVE-2019-11358",
            "affected_versions": ["1.0-3.3.1"],
            "severity": "medium",
            "description": "jQuery prototype pollution via extend function",
            "cvss": 6.1,
        },
    ],
    "redis:redis": [
        {
            "cve_id": "CVE-2022-0543",
            "affected_versions": ["2.2-6.2.6", "7.0.0-7.0.0"],
            "severity": "critical",
            "description": "Redis Lua sandbox escape and remote code execution",
            "cvss": 10.0,
        },
    ],
    "elastic:elasticsearch": [
        {
            "cve_id": "CVE-2021-22145",
            "affected_versions": ["7.0.0-7.13.3"],
            "severity": "medium",
            "description": "Elasticsearch memory disclosure vulnerability",
            "cvss": 6.5,
        },
    ],
}

# NVD API base URL
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVELookupScanner(BaseScanner):
    """CVE lookup scanner using NVD/NIST API and local database.

    Queries for known vulnerabilities based on detected technology stack.
    Uses CPE strings for precise matching and checks version ranges.
    """

    @property
    def module_name(self) -> str:
        return "cve_lookup"

    def parse_version(self, version_str: str) -> Optional[tuple[int, ...]]:
        """Parse a version string into a comparable tuple.

        Args:
            version_str: Version string like '2.4.49' or '7.13.3'.

        Returns:
            Tuple of integers for comparison, or None if unparseable.
        """
        if not version_str:
            return None
        # Extract numeric version parts
        match = re.match(r"([\d]+(?:\.[\d]+)*)", version_str)
        if match:
            parts = match.group(1).split(".")
            try:
                return tuple(int(p) for p in parts)
            except ValueError:
                return None
        return None

    def version_in_range(
        self, version: str, range_str: str
    ) -> bool:
        """Check if a version falls within a range specification.

        Args:
            version: Version string to check.
            range_str: Range like '2.4.0-2.4.55' or single version '2.4.49'.

        Returns:
            True if version is within the specified range.
        """
        parsed = self.parse_version(version)
        if parsed is None:
            return False

        if "-" in range_str:
            parts = range_str.split("-", 1)
            low = self.parse_version(parts[0])
            high = self.parse_version(parts[1])
            if low is None or high is None:
                return False
            return low <= parsed <= high
        else:
            target = self.parse_version(range_str)
            if target is None:
                return False
            return parsed == target

    def check_local_db(
        self, technology: str, version: str
    ) -> list[dict[str, Any]]:
        """Check the local CVE database for matching vulnerabilities.

        Args:
            technology: Technology name.
            version: Version string.

        Returns:
            List of matching CVE entries.
        """
        matches: list[dict[str, Any]] = []
        cpe_info = TECH_TO_CPE.get(technology)
        if not cpe_info:
            return matches

        vendor, product = cpe_info
        key = f"{vendor}:{product}"

        cves = KNOWN_CVES.get(key, [])
        for cve in cves:
            for affected_range in cve["affected_versions"]:
                if self.version_in_range(version, affected_range):
                    matches.append(cve)
                    break

        return matches

    async def query_nvd_api(
        self, technology: str, version: str
    ) -> list[dict[str, Any]]:
        """Query the NVD API for CVEs matching a technology and version.

        Args:
            technology: Technology name to look up.
            version: Version string.

        Returns:
            List of CVE entries from NVD.
        """
        cpe_info = TECH_TO_CPE.get(technology)
        if not cpe_info:
            return []

        vendor, product = cpe_info
        # Build CPE 2.3 string
        cpe_string = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

        params = {
            "cpeName": cpe_string,
            "resultsPerPage": "20",
        }

        # Add API key if configured
        headers = self.get_stealth_headers()
        api_key = self.config.get("nvd_api_key", "")
        if api_key:
            headers["apiKey"] = api_key

        results: list[dict[str, Any]] = []

        try:
            client = await self.get_http_client()
            response = await client.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=30.0,
            )

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")

                    # Extract description
                    descriptions = cve_data.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break

                    # Extract CVSS score and severity
                    metrics = cve_data.get("metrics", {})
                    cvss_score = 0.0
                    severity = "info"

                    # Try CVSS 3.1 first
                    cvss31 = metrics.get("cvssMetricV31", [])
                    if cvss31:
                        cvss_data = cvss31[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        base_severity = cvss_data.get("baseSeverity", "").lower()
                        severity = self._map_severity(base_severity)
                    else:
                        # Try CVSS 3.0
                        cvss30 = metrics.get("cvssMetricV30", [])
                        if cvss30:
                            cvss_data = cvss30[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            base_severity = cvss_data.get("baseSeverity", "").lower()
                            severity = self._map_severity(base_severity)

                    # Extract references
                    references = [
                        ref.get("url", "")
                        for ref in cve_data.get("references", [])
                    ]

                    results.append({
                        "cve_id": cve_id,
                        "severity": severity,
                        "description": description,
                        "cvss": cvss_score,
                        "references": references[:5],  # Limit references
                    })

            elif response.status_code == 403:
                await self.emit_event("nvd_rate_limited", {
                    "technology": technology,
                })
            elif response.status_code == 404:
                pass  # No results found

        except (httpx.HTTPError, httpx.TimeoutException, ValueError) as e:
            await self.emit_event("nvd_query_error", {
                "technology": technology,
                "error": str(e),
            })

        return results

    def _map_severity(self, nvd_severity: str) -> str:
        """Map NVD severity to our severity levels.

        Args:
            nvd_severity: NVD severity string.

        Returns:
            Mapped severity string.
        """
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "none": "info",
        }
        return mapping.get(nvd_severity, "info")

    async def run(self) -> list[dict[str, Any]]:
        """Execute CVE lookup based on provided technology stack.

        The scanner expects technology data in config['technologies'] as a list
        of dicts with 'technology' and 'version' keys.

        Returns:
            List of result dictionaries for discovered CVEs.
        """
        results: list[dict[str, Any]] = []
        technologies = self.config.get("technologies", [])

        if not technologies:
            await self.emit_event("cve_lookup_skipped", {
                "reason": "No technologies provided",
            })
            return results

        await self.emit_event("cve_lookup_started", {
            "technology_count": len(technologies),
        })

        for tech_info in technologies:
            technology = tech_info.get("technology", "")
            version = tech_info.get("version", "")

            if not technology:
                continue

            # Check local database first
            local_matches = self.check_local_db(technology, version)

            for cve in local_matches:
                result = self.build_result(
                    title=f"{cve['cve_id']}: {technology} {version}",
                    description=cve["description"],
                    severity=cve["severity"],
                    evidence=f"Technology: {technology} {version}, CVSS: {cve['cvss']}",
                    host=self.target,
                    protocol="http",
                    data={
                        "technology": technology,
                        "version": version,
                        "cvss_score": cve["cvss"],
                        "source": "local_db",
                    },
                    confidence=0.85 if version else 0.5,
                    cve_ids=[cve["cve_id"]],
                )
                results.append(result)

            # Query NVD API if version is available and not rate-limited
            if version and self.config.get("query_nvd", True):
                nvd_results = await self.query_nvd_api(technology, version)

                for cve in nvd_results:
                    # Skip if already found in local db
                    if any(r.get("cve_ids", [None])[0] == cve["cve_id"] for r in results if r.get("cve_ids")):
                        continue

                    result = self.build_result(
                        title=f"{cve['cve_id']}: {technology} {version}",
                        description=cve["description"][:500],
                        severity=cve["severity"],
                        evidence=f"Technology: {technology} {version}, CVSS: {cve['cvss']}",
                        host=self.target,
                        protocol="http",
                        data={
                            "technology": technology,
                            "version": version,
                            "cvss_score": cve["cvss"],
                            "references": cve["references"],
                            "source": "nvd_api",
                        },
                        confidence=0.9,
                        cve_ids=[cve["cve_id"]],
                    )
                    results.append(result)

                # Rate limiting: NVD allows ~5 requests per 30s without API key
                if not self.config.get("nvd_api_key"):
                    import asyncio
                    await asyncio.sleep(6.0)

        await self.emit_event("cve_lookup_completed", {
            "cves_found": len(results),
        })

        return results
