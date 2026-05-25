"""Async directory and file brute-force scanner.

Enumerates web directories and files using a built-in wordlist with
configurable extensions, status code filtering, and content-length
anomaly detection.
"""

import asyncio
import statistics
from typing import Any, Optional

import httpx

from recon_phantom.scanners.base import BaseScanner


# Built-in wordlist of common directories and files (~500 entries)
COMMON_WORDLIST: list[str] = [
    "admin", "administrator", "api", "app", "application", "assets", "auth",
    "backup", "backups", "bin", "blog", "cache", "cgi-bin", "cms", "common",
    "config", "configuration", "console", "content", "control", "controller",
    "cp", "cpanel", "css", "dashboard", "data", "database", "db", "debug",
    "default", "demo", "dev", "development", "dir", "doc", "docs",
    "documentation", "download", "downloads", "editor", "email", "engine",
    "env", "environment", "error", "errors", "example", "examples", "export",
    "extension", "extensions", "extra", "feed", "file", "files", "font",
    "fonts", "footer", "form", "forum", "framework", "frontend", "ftp",
    "function", "functions", "gateway", "global", "group", "groups",
    "guest", "handler", "header", "health", "help", "hidden", "home",
    "host", "html", "http", "icon", "icons", "image", "images", "img",
    "import", "include", "includes", "index", "info", "init", "install",
    "installer", "internal", "intranet", "issue", "issues", "java",
    "javascript", "job", "jobs", "js", "json", "key", "keys", "language",
    "languages", "layout", "layouts", "lib", "libraries", "library",
    "license", "link", "links", "list", "load", "local", "locale", "log",
    "logger", "logging", "login", "logout", "logs", "mail", "main",
    "maintenance", "manage", "manager", "manifest", "map", "master",
    "media", "member", "members", "menu", "message", "messages", "meta",
    "metrics", "middleware", "migration", "migrations", "misc", "mobile",
    "model", "models", "module", "modules", "monitor", "monitoring",
    "mount", "new", "news", "node", "node_modules", "notification",
    "notifications", "oauth", "old", "online", "option", "options",
    "order", "orders", "output", "package", "packages", "page", "pages",
    "panel", "param", "params", "partner", "partners", "password",
    "path", "payment", "payments", "php", "phpinfo", "phpmyadmin",
    "ping", "plugin", "plugins", "policy", "portal", "post", "posts",
    "preview", "private", "proc", "process", "production", "profile",
    "profiles", "project", "projects", "properties", "property",
    "protected", "proxy", "public", "query", "queue", "raw", "readme",
    "recovery", "redirect", "register", "release", "releases", "remote",
    "render", "report", "reports", "repository", "request", "requests",
    "reset", "resource", "resources", "response", "rest", "result",
    "results", "robots", "robots.txt", "root", "route", "router",
    "routes", "rss", "rule", "rules", "run", "runtime", "sample",
    "samples", "save", "schedule", "schema", "script", "scripts",
    "search", "secret", "secrets", "secure", "security", "seed",
    "server", "service", "services", "session", "sessions", "setting",
    "settings", "setup", "share", "shared", "shell", "shop", "signin",
    "signup", "site", "sitemap", "sitemap.xml", "socket", "source",
    "sql", "src", "ssl", "staff", "stage", "staging", "start",
    "static", "statistics", "stats", "status", "storage", "store",
    "stream", "style", "styles", "stylesheet", "stylesheets", "submit",
    "support", "swagger", "sync", "sys", "system", "tag", "tags",
    "task", "tasks", "team", "teams", "temp", "template", "templates",
    "temporary", "terms", "test", "testing", "tests", "text", "theme",
    "themes", "ticket", "tickets", "tmp", "token", "tokens", "tool",
    "tools", "topic", "topics", "trace", "track", "tracking", "traffic",
    "transfer", "trash", "tree", "trigger", "type", "types", "ui",
    "undefined", "unit", "update", "updates", "upgrade", "upload",
    "uploads", "url", "user", "users", "util", "utilities", "utils",
    "v1", "v2", "v3", "validate", "validation", "value", "values",
    "var", "vendor", "vendors", "version", "versions", "video", "videos",
    "view", "views", "virtual", "volume", "war", "web", "webapp",
    "webmail", "webpack", "website", "widget", "widgets", "wiki",
    "wordpress", "work", "worker", "workers", "workspace", "wp",
    "wp-admin", "wp-content", "wp-includes", "wp-json", "wp-login",
    "wp-login.php", "write", "xml", "xmlrpc", "xmlrpc.php", "yaml",
    "zone", "zones",
    # Common files
    ".env", ".git", ".gitignore", ".htaccess", ".htpasswd", ".svn",
    ".DS_Store", "Thumbs.db", "composer.json", "package.json",
    "Dockerfile", "docker-compose.yml", "Makefile", "Gruntfile.js",
    "Gulpfile.js", "webpack.config.js", "tsconfig.json", ".babelrc",
    "yarn.lock", "Gemfile", "requirements.txt", "Pipfile", "go.mod",
    "Cargo.toml", "pom.xml", "build.gradle", "web.config", "server.xml",
    "application.yml", "application.properties", "appsettings.json",
    "config.php", "config.yml", "config.json", "database.yml",
    "settings.py", "manage.py", "artisan", "console", "phpunit.xml",
    "README.md", "CHANGELOG.md", "LICENSE", "TODO", "INSTALL",
    "crossdomain.xml", "clientaccesspolicy.xml", "browserconfig.xml",
    "manifest.json", "service-worker.js", "sw.js", "firebase-messaging-sw.js",
    "OneSignalSDKWorker.js", "ads.txt", "app-ads.txt", "security.txt",
    ".well-known/security.txt", ".well-known/openid-configuration",
    "graphql", "graphiql", "playground", "explorer",
    "actuator", "actuator/health", "actuator/env", "actuator/info",
    "metrics", "healthcheck", "health-check", "_health",
    "server-status", "server-info", "nginx_status",
    "elmah.axd", "trace.axd", "phpinfo.php", "info.php", "test.php",
]

# Extensions to try appending
DEFAULT_EXTENSIONS: list[str] = [
    "", ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".json",
    ".xml", ".txt", ".bak", ".old", ".orig", ".tmp", ".swp",
]

# Status codes indicating found resources
FOUND_STATUS_CODES: set[int] = {200, 201, 204, 301, 302, 307, 308, 401, 403}

# Status codes indicating protected but existing resources
INTERESTING_STATUS_CODES: set[int] = {401, 403, 405, 500, 502, 503}


class DirectoryBruteforceScanner(BaseScanner):
    """Async directory and file enumeration scanner.

    Brute-forces web directories using a comprehensive wordlist with
    configurable extensions. Detects anomalies in response patterns
    to identify hidden content.
    """

    @property
    def module_name(self) -> str:
        return "directory_bruteforce"

    async def _get_baseline(self, base_url: str) -> dict[str, Any]:
        """Establish baseline response for 404 detection.

        Args:
            base_url: Base URL of the target.

        Returns:
            Baseline information dict with typical 404 characteristics.
        """
        baseline: dict[str, Any] = {
            "status_code": 404,
            "content_lengths": [],
            "avg_content_length": 0,
            "std_content_length": 0,
        }

        # Request several known non-existent paths to establish baseline
        test_paths = [
            f"/thisdoesnotexist_{i}_randompath123" for i in range(5)
        ]

        for path in test_paths:
            url = f"{base_url}{path}"
            response = await self.make_request(url, follow_redirects=False)
            if response:
                baseline["status_code"] = response.status_code
                content_length = len(response.content)
                baseline["content_lengths"].append(content_length)

        if baseline["content_lengths"]:
            baseline["avg_content_length"] = statistics.mean(
                baseline["content_lengths"]
            )
            if len(baseline["content_lengths"]) > 1:
                baseline["std_content_length"] = statistics.stdev(
                    baseline["content_lengths"]
                )

        return baseline

    def _is_anomalous(
        self, response: httpx.Response, baseline: dict[str, Any]
    ) -> bool:
        """Detect if a response is anomalous compared to baseline.

        Args:
            response: HTTP response to check.
            baseline: Baseline 404 characteristics.

        Returns:
            True if the response differs significantly from baseline.
        """
        content_length = len(response.content)
        avg = baseline["avg_content_length"]
        std = baseline["std_content_length"]

        # If content length differs significantly from 404 baseline
        if std > 0:
            z_score = abs(content_length - avg) / std
            return z_score > 2.0
        elif avg > 0:
            # No std available, check for >20% difference
            diff_ratio = abs(content_length - avg) / avg
            return diff_ratio > 0.2

        return content_length > 0

    async def check_path(
        self,
        base_url: str,
        path: str,
        semaphore: asyncio.Semaphore,
        baseline: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        """Check a single path for existence.

        Args:
            base_url: Base URL of the target.
            path: Path to check.
            semaphore: Concurrency semaphore.
            baseline: Baseline 404 response data.

        Returns:
            Finding dict if path exists, None otherwise.
        """
        async with semaphore:
            url = f"{base_url}/{path.lstrip('/')}"
            follow_redirects = self.config.get("follow_redirects", False)

            response = await self.make_request(
                url, follow_redirects=follow_redirects
            )

            if response is None:
                return None

            status = response.status_code
            content_length = len(response.content)

            # Skip if matches baseline 404
            if status == baseline["status_code"]:
                if not self._is_anomalous(response, baseline):
                    return None

            # Check if it's a valid finding
            if status in FOUND_STATUS_CODES:
                # Determine redirect target if applicable
                redirect_url = ""
                if status in (301, 302, 307, 308):
                    redirect_url = response.headers.get("location", "")

                return {
                    "path": path,
                    "url": url,
                    "status_code": status,
                    "content_length": content_length,
                    "content_type": response.headers.get("content-type", ""),
                    "redirect_url": redirect_url,
                    "interesting": status in INTERESTING_STATUS_CODES,
                }

            return None

    def _get_wordlist(self) -> list[str]:
        """Get the wordlist to use for enumeration.

        Returns:
            List of paths to check.
        """
        custom_wordlist = self.config.get("wordlist", None)
        if custom_wordlist and isinstance(custom_wordlist, list):
            return custom_wordlist
        return COMMON_WORDLIST

    def _get_extensions(self) -> list[str]:
        """Get file extensions to append to wordlist entries.

        Returns:
            List of extensions (including empty string for no extension).
        """
        custom_extensions = self.config.get("extensions", None)
        if custom_extensions and isinstance(custom_extensions, list):
            return custom_extensions
        return self.config.get("default_extensions", ["", ".php", ".html", ".bak"])

    def _generate_paths(self) -> list[str]:
        """Generate all paths to check from wordlist and extensions.

        Returns:
            Complete list of paths to enumerate.
        """
        wordlist = self._get_wordlist()
        extensions = self._get_extensions()
        paths: list[str] = []

        for word in wordlist:
            # If the word already has an extension or is a file, don't add more
            if "." in word.split("/")[-1]:
                paths.append(word)
            else:
                for ext in extensions:
                    paths.append(f"{word}{ext}")

        return list(set(paths))  # Deduplicate

    async def run(self) -> list[dict[str, Any]]:
        """Execute directory brute-force scan.

        Returns:
            List of result dictionaries for discovered paths.
        """
        results: list[dict[str, Any]] = []

        # Determine base URL
        if self.target.startswith(("http://", "https://")):
            base_url = self.target.rstrip("/")
        else:
            base_url = f"https://{self.target}"

        await self.emit_event("dirbrute_started", {"base_url": base_url})

        # Establish baseline for 404 detection
        baseline = await self._get_baseline(base_url)

        # Generate paths
        paths = self._generate_paths()
        await self.emit_event("dirbrute_paths_generated", {
            "path_count": len(paths),
        })

        # Scan paths concurrently
        semaphore = self.get_semaphore()
        tasks = [
            self.check_path(base_url, path, semaphore, baseline)
            for path in paths
        ]

        findings = await asyncio.gather(*tasks, return_exceptions=True)

        # Process findings
        for finding in findings:
            if isinstance(finding, dict) and finding is not None:
                severity = "info"
                title = f"Directory/file found: /{finding['path']}"

                # Determine severity based on what was found
                path_lower = finding["path"].lower()
                if any(s in path_lower for s in [".env", "config", "secret", "password", "key"]):
                    severity = "high"
                    title = f"Sensitive file exposed: /{finding['path']}"
                elif any(s in path_lower for s in [".git", ".svn", "backup", ".bak"]):
                    severity = "high"
                    title = f"Version control/backup exposed: /{finding['path']}"
                elif any(s in path_lower for s in ["admin", "panel", "console", "dashboard"]):
                    severity = "medium"
                    title = f"Admin interface found: /{finding['path']}"
                elif any(s in path_lower for s in ["phpinfo", "server-status", "server-info"]):
                    severity = "medium"
                    title = f"Information disclosure: /{finding['path']}"
                elif finding["status_code"] in (401, 403):
                    severity = "low"
                    title = f"Protected resource: /{finding['path']}"

                description = (
                    f"HTTP {finding['status_code']} at {finding['url']}"
                    f" (Content-Length: {finding['content_length']})"
                )
                if finding["redirect_url"]:
                    description += f" -> {finding['redirect_url']}"

                result = self.build_result(
                    title=title,
                    description=description,
                    severity=severity,
                    evidence=f"HTTP {finding['status_code']} {finding['url']}",
                    host=self.target,
                    path=f"/{finding['path']}",
                    protocol="https" if "https" in base_url else "http",
                    data={
                        "status_code": finding["status_code"],
                        "content_length": finding["content_length"],
                        "content_type": finding["content_type"],
                        "redirect_url": finding["redirect_url"],
                    },
                    confidence=0.9 if finding["status_code"] == 200 else 0.7,
                )
                results.append(result)

        await self.emit_event("dirbrute_completed", {
            "paths_found": len(results),
            "total_checked": len(paths),
        })

        return results
