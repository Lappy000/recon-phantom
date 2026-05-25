"""Git and Sensitive File Exposure Detection module.

Checks for exposed version control artifacts, backup files, configuration
files, and other sensitive paths that should not be publicly accessible.
"""

import asyncio
import re
from typing import Any, Optional

import httpx

from recon_phantom.scanners.base import BaseScanner


# Sensitive paths to check with their metadata
SENSITIVE_PATHS: list[dict[str, Any]] = [
    {
        "path": "/.git/HEAD",
        "name": "Git HEAD Reference",
        "description": "Git repository HEAD file exposed, indicating full .git directory access.",
        "severity": "critical",
        "validation": r"^ref: refs/",
        "category": "version_control",
    },
    {
        "path": "/.git/config",
        "name": "Git Configuration",
        "description": "Git configuration file exposed. May contain remote URLs, credentials, or internal paths.",
        "severity": "critical",
        "validation": r"\[core\]|\[remote",
        "category": "version_control",
    },
    {
        "path": "/.git/objects/",
        "name": "Git Objects Directory",
        "description": "Git objects directory is listable. Full repository content may be reconstructable.",
        "severity": "critical",
        "validation": r"(pack|info|Index of|<title>)",
        "category": "version_control",
    },
    {
        "path": "/.git/logs/HEAD",
        "name": "Git Reflog",
        "description": "Git reflog exposed. Contains commit history with author information.",
        "severity": "high",
        "validation": r"[0-9a-f]{40}",
        "category": "version_control",
    },
    {
        "path": "/.git/COMMIT_EDITMSG",
        "name": "Git Last Commit Message",
        "description": "Last git commit message file is accessible.",
        "severity": "medium",
        "validation": None,
        "category": "version_control",
    },
    {
        "path": "/.git/description",
        "name": "Git Repository Description",
        "description": "Git repository description file accessible.",
        "severity": "low",
        "validation": None,
        "category": "version_control",
    },
    {
        "path": "/.git/packed-refs",
        "name": "Git Packed References",
        "description": "Git packed references file exposed. Contains branch and tag SHA hashes.",
        "severity": "high",
        "validation": r"[0-9a-f]{40} refs/",
        "category": "version_control",
    },
    {
        "path": "/.gitignore",
        "name": "Gitignore File",
        "description": "Gitignore file reveals project structure and potentially sensitive file paths.",
        "severity": "low",
        "validation": r"(\*\.|#|/|node_modules|\.env)",
        "category": "version_control",
    },
    {
        "path": "/.env",
        "name": "Environment Configuration (.env)",
        "description": "Environment file exposed! Likely contains API keys, database credentials, and secrets.",
        "severity": "critical",
        "validation": r"(DB_|API_|SECRET|PASSWORD|KEY|TOKEN|AWS_).*=",
        "category": "credentials",
    },
    {
        "path": "/.env.local",
        "name": "Local Environment Configuration",
        "description": "Local environment override file exposed with potential credentials.",
        "severity": "critical",
        "validation": r"(DB_|API_|SECRET|PASSWORD|KEY|TOKEN).*=",
        "category": "credentials",
    },
    {
        "path": "/.env.production",
        "name": "Production Environment Configuration",
        "description": "Production environment file exposed! Contains production credentials.",
        "severity": "critical",
        "validation": r"(DB_|API_|SECRET|PASSWORD|KEY|TOKEN).*=",
        "category": "credentials",
    },
    {
        "path": "/.env.backup",
        "name": "Environment Backup File",
        "description": "Backup of environment configuration found with potential credentials.",
        "severity": "critical",
        "validation": r"(DB_|API_|SECRET|PASSWORD|KEY|TOKEN).*=",
        "category": "credentials",
    },
    {
        "path": "/wp-config.php.bak",
        "name": "WordPress Config Backup",
        "description": "WordPress configuration backup file exposed. Contains database credentials.",
        "severity": "critical",
        "validation": r"(DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|define\()",
        "category": "backup",
    },
    {
        "path": "/wp-config.php~",
        "name": "WordPress Config Editor Backup",
        "description": "Editor backup of WordPress config with database credentials.",
        "severity": "critical",
        "validation": r"(DB_NAME|DB_USER|DB_PASSWORD|define\()",
        "category": "backup",
    },
    {
        "path": "/wp-config.php.old",
        "name": "WordPress Config Old Backup",
        "description": "Old WordPress configuration file with potential credentials.",
        "severity": "critical",
        "validation": r"(DB_NAME|DB_USER|DB_PASSWORD|define\()",
        "category": "backup",
    },
    {
        "path": "/.DS_Store",
        "name": "macOS .DS_Store File",
        "description": "macOS directory metadata file exposed. Reveals directory structure and filenames.",
        "severity": "medium",
        "validation": r"(\x00\x00\x00\x01Bud1|Bud1)",
        "binary_check": True,
        "category": "metadata",
    },
    {
        "path": "/backup.sql",
        "name": "SQL Database Backup",
        "description": "Database backup file publicly accessible! May contain all application data.",
        "severity": "critical",
        "validation": r"(CREATE TABLE|INSERT INTO|DROP TABLE|mysqldump|pg_dump)",
        "category": "backup",
    },
    {
        "path": "/database.sql",
        "name": "SQL Database Export",
        "description": "Database export file found. Contains database schema and data.",
        "severity": "critical",
        "validation": r"(CREATE TABLE|INSERT INTO|DROP TABLE|mysqldump)",
        "category": "backup",
    },
    {
        "path": "/dump.sql",
        "name": "SQL Database Dump",
        "description": "Database dump file publicly accessible.",
        "severity": "critical",
        "validation": r"(CREATE TABLE|INSERT INTO|DROP TABLE|mysqldump)",
        "category": "backup",
    },
    {
        "path": "/.svn/entries",
        "name": "SVN Entries File",
        "description": "Subversion repository metadata exposed. Reveals file structure.",
        "severity": "high",
        "validation": r"(dir|svn://|http://)",
        "category": "version_control",
    },
    {
        "path": "/.hg/hgrc",
        "name": "Mercurial Configuration",
        "description": "Mercurial repository configuration exposed.",
        "severity": "high",
        "validation": r"\[paths\]|\[ui\]",
        "category": "version_control",
    },
    {
        "path": "/config.php.bak",
        "name": "PHP Config Backup",
        "description": "PHP configuration backup file exposed with potential credentials.",
        "severity": "high",
        "validation": r"(\$db|\$config|\$password|define\()",
        "category": "backup",
    },
    {
        "path": "/web.config",
        "name": "IIS Web.config",
        "description": "IIS web.config file accessible. May contain connection strings and settings.",
        "severity": "high",
        "validation": r"(<configuration|<connectionStrings|<appSettings)",
        "category": "configuration",
    },
    {
        "path": "/phpinfo.php",
        "name": "PHP Info Page",
        "description": "phpinfo() page accessible. Reveals server configuration and environment.",
        "severity": "medium",
        "validation": r"(phpinfo|PHP Version|PHP Credits)",
        "category": "information_disclosure",
    },
    {
        "path": "/server-status",
        "name": "Apache Server Status",
        "description": "Apache mod_status page exposed. Shows active connections and server info.",
        "severity": "medium",
        "validation": r"(Apache Server Status|Server Version)",
        "category": "information_disclosure",
    },
    {
        "path": "/.htpasswd",
        "name": "Apache Password File",
        "description": "Apache htpasswd file exposed! Contains hashed credentials.",
        "severity": "critical",
        "validation": r"^[a-zA-Z0-9_-]+:\$|^[a-zA-Z0-9_-]+:\{",
        "category": "credentials",
    },
    {
        "path": "/.htaccess",
        "name": "Apache Htaccess File",
        "description": "Apache .htaccess file readable. Reveals URL rewrite rules and configurations.",
        "severity": "medium",
        "validation": r"(RewriteRule|RewriteEngine|AuthType|Deny from)",
        "category": "configuration",
    },
    {
        "path": "/crossdomain.xml",
        "name": "Flash Cross-Domain Policy",
        "description": "Cross-domain policy file found. May allow unauthorized cross-origin access.",
        "severity": "low",
        "validation": r"<cross-domain-policy",
        "category": "configuration",
    },
]


class GitExposureScanner(BaseScanner):
    """Detects exposed Git repositories, backup files, and sensitive paths.

    Systematically checks for common sensitive file paths that are frequently
    left exposed on web servers, including version control artifacts, backup
    files, environment configurations, and debug endpoints.
    """

    @property
    def module_name(self) -> str:
        return "git_exposure"

    async def run(self) -> list[dict[str, Any]]:
        """Execute the sensitive file exposure scan.

        Returns:
            List of findings for exposed sensitive files and paths.
        """
        results: list[dict[str, Any]] = []
        base_url = self.get_base_url("https")

        await self.emit_event("git_exposure_scan_started", {"url": base_url})

        # Check all sensitive paths concurrently
        semaphore = self.get_semaphore()

        async def check_path(path_info: dict[str, Any]) -> Optional[dict[str, Any]]:
            async with semaphore:
                return await self._check_sensitive_path(base_url, path_info)

        tasks = [check_path(p) for p in SENSITIVE_PATHS]
        check_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in check_results:
            if isinstance(result, dict):
                results.append(result)
            elif isinstance(result, Exception):
                await self.emit_event("path_check_error", {"error": str(result)})

        # If .git/HEAD was found, try to extract more info
        git_head_found = any(
            r.get("path") == "/.git/HEAD" for r in results
        )
        if git_head_found:
            extra_results = await self._deep_git_enumeration(base_url)
            results.extend(extra_results)

        # Summary
        categories: dict[str, int] = {}
        for r in results:
            cat = r.get("data", {}).get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1

        if results:
            results.append(self.build_result(
                title=f"Sensitive File Exposure Summary: {len(results)} files found",
                description=(
                    f"Found {len(results)} exposed sensitive files across categories: "
                    + ", ".join(f"{k}: {v}" for k, v in sorted(categories.items()))
                ),
                severity="info",
                host=self.target,
                data={
                    "total_exposed": len(results),
                    "categories": categories,
                    "paths_checked": len(SENSITIVE_PATHS),
                },
                confidence=0.95,
            ))

        await self.emit_event("git_exposure_scan_completed", {
            "findings": len(results),
            "paths_checked": len(SENSITIVE_PATHS),
        })
        return results

    async def _check_sensitive_path(
        self, base_url: str, path_info: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """Check a single path for exposure.

        Returns:
            Result dictionary if the path is exposed, None otherwise.
        """
        url = f"{base_url}{path_info['path']}"
        response = await self.make_request(url, follow_redirects=False)

        if response is None:
            return None

        # Only consider 200 OK responses as exposed
        if response.status_code != 200:
            return None

        # Validate content if a validation pattern is provided
        body = response.text[:10000] if response.text else ""
        is_binary = path_info.get("binary_check", False)

        if path_info.get("validation"):
            pattern = path_info["validation"]
            if is_binary:
                # For binary files, check raw bytes
                raw = response.content[:1000] if response.content else b""
                raw_str = raw.decode("latin-1", errors="ignore")
                if not re.search(pattern, raw_str, re.IGNORECASE | re.MULTILINE):
                    return None
            else:
                if not re.search(pattern, body, re.IGNORECASE | re.MULTILINE):
                    # Content doesn't match expected pattern - likely a custom 404
                    return None

        # Additional false positive checks
        if self._is_likely_false_positive(response, body, path_info):
            return None

        # Build evidence (truncated for safety)
        evidence = self._build_evidence(body, path_info, response)

        return self.build_result(
            title=f"Exposed: {path_info['name']}",
            description=path_info["description"],
            severity=path_info["severity"],
            evidence=evidence,
            host=self.target,
            path=path_info["path"],
            protocol="https",
            data={
                "category": path_info["category"],
                "url": url,
                "content_length": len(body),
                "content_type": response.headers.get("content-type", ""),
                "status_code": response.status_code,
            },
            confidence=0.9 if path_info.get("validation") else 0.7,
        )

    def _is_likely_false_positive(
        self, response: httpx.Response, body: str, path_info: dict[str, Any]
    ) -> bool:
        """Check if the response is likely a soft 404 or false positive."""
        content_type = response.headers.get("content-type", "").lower()

        # HTML response for non-HTML expected files is usually a custom 404
        if path_info["category"] in ("version_control", "credentials", "backup"):
            if "text/html" in content_type and path_info["path"].endswith(
                (".sql", ".env", ".bak", ".old")
            ):
                # Check if it looks like a 404 page
                lower_body = body.lower()
                false_positive_indicators = [
                    "page not found",
                    "404 not found",
                    "not found",
                    "error 404",
                    "does not exist",
                ]
                if any(ind in lower_body for ind in false_positive_indicators):
                    return True

        # Very small responses might be empty/placeholder
        if len(body.strip()) < 3 and not path_info.get("binary_check"):
            return True

        return False

    def _build_evidence(
        self, body: str, path_info: dict[str, Any], response: httpx.Response
    ) -> str:
        """Build evidence string with sanitized content."""
        evidence_lines = [
            f"URL: {response.url}",
            f"Status: {response.status_code}",
            f"Content-Type: {response.headers.get('content-type', 'unknown')}",
            f"Content-Length: {len(body)}",
            "---",
        ]

        # Sanitize sensitive content - show structure but redact values
        if path_info["category"] == "credentials":
            # Redact actual credential values
            sanitized = self._redact_credentials(body[:500])
            evidence_lines.append(f"Content (redacted):\n{sanitized}")
        else:
            # Show first portion of content
            evidence_lines.append(f"Content preview:\n{body[:300]}")

        return "\n".join(evidence_lines)

    def _redact_credentials(self, text: str) -> str:
        """Redact sensitive values from credential files."""
        lines = text.split("\n")
        redacted_lines = []
        for line in lines[:20]:  # Only show first 20 lines
            if "=" in line and not line.strip().startswith("#"):
                key, _, value = line.partition("=")
                if any(kw in key.upper() for kw in
                       ("PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL")):
                    redacted_lines.append(f"{key}=[REDACTED]")
                else:
                    redacted_lines.append(f"{key}={value[:3]}***")
            else:
                redacted_lines.append(line)
        return "\n".join(redacted_lines)

    async def _deep_git_enumeration(self, base_url: str) -> list[dict[str, Any]]:
        """Perform deeper Git repository enumeration after initial detection.

        Attempts to extract branch names, recent commits, and repository structure.
        """
        results: list[dict[str, Any]] = []

        # Try to read current branch from HEAD
        head_url = f"{base_url}/.git/HEAD"
        response = await self.make_request(head_url)
        if response and response.status_code == 200:
            head_content = response.text.strip()
            branch_match = re.match(r"ref: refs/heads/(.+)", head_content)
            if branch_match:
                branch = branch_match.group(1)

                # Try to get the commit hash for this branch
                ref_url = f"{base_url}/.git/refs/heads/{branch}"
                ref_response = await self.make_request(ref_url)
                commit_hash = ""
                if ref_response and ref_response.status_code == 200:
                    commit_hash = ref_response.text.strip()[:40]

                results.append(self.build_result(
                    title=f"Git Branch Exposed: {branch}",
                    description=(
                        f"Active branch '{branch}' identified. "
                        f"{'Latest commit: ' + commit_hash if commit_hash else ''} "
                        "The repository can likely be fully reconstructed."
                    ),
                    severity="critical",
                    evidence=f"HEAD: {head_content}\nCommit: {commit_hash}",
                    host=self.target,
                    path="/.git/HEAD",
                    data={
                        "branch": branch,
                        "commit_hash": commit_hash,
                        "reconstructable": True,
                    },
                    confidence=0.95,
                ))

        # Try to read git config for remote URLs
        config_url = f"{base_url}/.git/config"
        config_response = await self.make_request(config_url)
        if config_response and config_response.status_code == 200:
            config_text = config_response.text
            remote_urls = re.findall(
                r'url\s*=\s*(.+)', config_text
            )
            if remote_urls:
                results.append(self.build_result(
                    title="Git Remote URLs Exposed",
                    description=(
                        "Git remote repository URLs found in configuration. "
                        "May reveal internal infrastructure or private repositories."
                    ),
                    severity="high",
                    evidence="\n".join(f"Remote: {url.strip()}" for url in remote_urls),
                    host=self.target,
                    path="/.git/config",
                    data={"remote_urls": [u.strip() for u in remote_urls]},
                    confidence=0.95,
                ))

        return results
