"""Built-in wordlists for subdomain enumeration and directory bruteforcing.

Provides curated wordlists commonly used in reconnaissance without requiring
external file dependencies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


# Top 200 subdomain prefixes for enumeration
TOP_SUBDOMAINS: list[str] = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "www1", "intranet", "portal",
    "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3",
    "dns", "search", "staging", "server", "mx1", "chat", "wap", "my", "svn",
    "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2",
    "lyncdiscover", "info", "apps", "download", "remote", "db", "forums", "store",
    "relay", "files", "newsletter", "app", "live", "owa", "en", "start", "sms",
    "office", "exchange", "ipv4", "mail3", "help", "blogs", "helpdesk", "web1",
    "home", "library", "ftp2", "ntp", "monitor", "login", "service", "correo",
    "www4", "moodle", "it", "gateway", "gw", "i", "stat", "stage", "ldap",
    "tv", "ssl", "web2", "ns5", "upload", "nagios", "smtp2", "online", "ad",
    "survey", "data", "radio", "extranet", "test2", "mssql", "dns3", "jobs",
    "services", "panel", "irc", "hosting", "cloud", "de", "gmail", "s", "bbs",
    "cs", "ww", "mrtg", "git", "image", "members", "poczta", "s1", "meet",
    "preview", "fr", "cloudflare-resolve-to", "dev2", "photo", "jabber", "legacy",
    "go", "es", "ssh", "redmine", "partner", "vps", "server1", "sv", "ns6",
    "webmail2", "av", "community", "cacti", "time", "sftp", "lib", "facebook",
    "www5", "smtp1", "feeds", "tracker", "qa", "accounts", "jenkins", "gitlab",
    "docker", "grafana", "prometheus", "kibana", "elastic", "redis", "mongo",
    "postgres", "kafka", "rabbitmq", "vault", "consul", "nomad", "terraform",
    "ansible", "puppet", "k8s", "kubernetes", "rancher", "harbor", "registry",
]

# Top 300 directory/file paths for brute forcing
TOP_DIRECTORIES: list[str] = [
    "", "admin", "login", "wp-admin", "administrator", "wp-login.php", "admin.php",
    "wp-content", "wp-includes", "images", "js", "css", "uploads", "includes",
    "install", "tmp", "temp", "backup", "backups", "bak", "old", "new", "test",
    "testing", "dev", "development", "staging", "demo", "beta", "alpha", "config",
    "configuration", "conf", "settings", "setup", "api", "api/v1", "api/v2",
    "rest", "graphql", "swagger", "docs", "documentation", "doc", "help", "faq",
    "about", "contact", "support", "status", "health", "ping", "info", "version",
    "robots.txt", "sitemap.xml", "crossdomain.xml", ".well-known", "favicon.ico",
    ".env", ".git", ".git/config", ".git/HEAD", ".gitignore", ".htaccess",
    ".htpasswd", "wp-config.php", "web.config", "server-status", "server-info",
    "phpinfo.php", "info.php", "test.php", "debug", "trace", "console",
    "phpmyadmin", "pma", "mysql", "myadmin", "adminer", "sql", "database",
    "db", "data", "dump", "export", "import", "migrate", "migration",
    "user", "users", "account", "accounts", "profile", "profiles", "register",
    "signup", "signin", "auth", "authenticate", "authorization", "oauth",
    "token", "session", "sessions", "logout", "password", "reset", "forgot",
    "dashboard", "panel", "control", "manage", "manager", "management",
    "cms", "editor", "blog", "posts", "articles", "news", "feed", "rss",
    "atom", "archive", "archives", "category", "categories", "tag", "tags",
    "search", "query", "find", "results", "page", "pages", "post", "entry",
    "upload", "uploads", "file", "files", "media", "assets", "static",
    "public", "private", "internal", "external", "resources", "resource",
    "download", "downloads", "attachment", "attachments", "document", "documents",
    "report", "reports", "log", "logs", "error", "errors", "404", "500",
    "cgi-bin", "cgi", "bin", "scripts", "script", "shell", "cmd", "command",
    "exec", "execute", "run", "process", "system", "sys", "admin/login",
    "admin/dashboard", "admin/config", "admin/users", "admin/settings",
    "wp-json", "wp-json/wp/v2", "xmlrpc.php", "readme.html", "license.txt",
    "changelog.txt", "CHANGELOG.md", "README.md", "package.json", "composer.json",
    "Gemfile", "requirements.txt", "Dockerfile", "docker-compose.yml",
    ".dockerignore", "Makefile", "Vagrantfile", "Procfile",
    "node_modules", "vendor", "bower_components", "dist", "build", "target",
    "out", "output", "release", "deploy", "deployment",
    "socket", "websocket", "ws", "wss", "stream", "event", "events",
    "webhook", "webhooks", "callback", "hook", "hooks", "notify", "notification",
    "email", "mail", "smtp", "imap", "pop", "message", "messages", "inbox",
    "chat", "messenger", "communication", "ticket", "tickets", "issue", "issues",
    "task", "tasks", "project", "projects", "workspace", "workspaces",
    "team", "teams", "group", "groups", "org", "organization", "company",
    "shop", "store", "cart", "checkout", "payment", "payments", "order", "orders",
    "product", "products", "catalog", "inventory", "invoice", "invoices",
    "billing", "subscription", "subscriptions", "plan", "plans", "pricing",
    "metrics", "analytics", "statistics", "stats", "monitor", "monitoring",
    "trace", "traces", "span", "health/live", "health/ready", "actuator",
    "actuator/health", "actuator/info", "actuator/env", "prometheus", "grafana",
    ".DS_Store", "thumbs.db", "desktop.ini", ".svn", ".svn/entries",
    ".hg", ".bzr", "CVS", "WEB-INF", "META-INF",
    "elmah.axd", "trace.axd", "web.config.bak", "Global.asax",
]

# Common file extensions for appending to paths
COMMON_EXTENSIONS: list[str] = [
    ".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action",
    ".html", ".htm", ".shtml", ".xhtml",
    ".js", ".json", ".xml", ".yaml", ".yml",
    ".txt", ".md", ".csv", ".log",
    ".sql", ".db", ".sqlite", ".mdb",
    ".bak", ".backup", ".old", ".orig", ".copy", ".tmp", ".temp",
    ".conf", ".config", ".cfg", ".ini", ".env",
    ".zip", ".tar", ".gz", ".tar.gz", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".sh", ".bash", ".py", ".rb", ".pl", ".cgi",
    ".swp", ".swo", ".swn",  # Vim swap files
    ".DS_Store",
]


def load_wordlist(source: str, custom_path: Optional[str] = None) -> list[str]:
    """Load a wordlist from built-in sources or a custom file.

    Args:
        source: Wordlist identifier. Built-in options:
            - 'builtin:subdomains' - Top subdomain prefixes
            - 'builtin:directories' - Common directory paths
            - 'builtin:extensions' - File extensions
            - 'builtin:top1000' - Alias for subdomains
            - 'builtin:common' - Alias for directories
            - Any file path for custom wordlists
        custom_path: Override path for file-based wordlists.

    Returns:
        List of wordlist entries.

    Raises:
        FileNotFoundError: If custom wordlist file doesn't exist.
        ValueError: If source identifier is unknown.
    """
    builtin_map = {
        "builtin:subdomains": TOP_SUBDOMAINS,
        "builtin:top1000": TOP_SUBDOMAINS,
        "builtin:directories": TOP_DIRECTORIES,
        "builtin:common": TOP_DIRECTORIES,
        "builtin:extensions": COMMON_EXTENSIONS,
    }

    # Check built-in wordlists
    if source in builtin_map:
        return builtin_map[source].copy()

    # Try loading from file
    file_path = Path(custom_path) if custom_path else Path(source)
    if file_path.exists():
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        # Filter empty lines and comments
        return [
            line.strip()
            for line in lines
            if line.strip() and not line.strip().startswith("#")
        ]

    raise ValueError(
        f"Unknown wordlist source: {source}. "
        f"Available built-in lists: {list(builtin_map.keys())}"
    )


def get_subdomain_wordlist(size: str = "medium") -> list[str]:
    """Get subdomain wordlist of specified size.

    Args:
        size: 'small' (50), 'medium' (100), 'large' (200).

    Returns:
        Subdomain wordlist.
    """
    sizes = {"small": 50, "medium": 100, "large": 200}
    count = sizes.get(size, 100)
    return TOP_SUBDOMAINS[:count]


def get_directory_wordlist(size: str = "medium") -> list[str]:
    """Get directory wordlist of specified size.

    Args:
        size: 'small' (100), 'medium' (200), 'large' (300).

    Returns:
        Directory path wordlist.
    """
    sizes = {"small": 100, "medium": 200, "large": 300}
    count = sizes.get(size, 200)
    return TOP_DIRECTORIES[:count]
