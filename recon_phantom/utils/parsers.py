"""Banner parsing, version extraction, and service identification utilities.

Provides regex-based extraction of software versions from service banners,
CPE string generation, and service identification heuristics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceInfo:
    """Parsed service information from a banner."""

    product: str
    version: str = ""
    vendor: str = ""
    os: str = ""
    cpe: str = ""
    extra_info: str = ""
    confidence: float = 0.8


# Version extraction patterns: (regex, product, vendor)
VERSION_PATTERNS: list[tuple[str, str, str]] = [
    # SSH
    (r"SSH-[\d.]+-OpenSSH[_\s]+([\d.p]+)", "OpenSSH", "OpenBSD"),
    (r"SSH-[\d.]+-dropbear[_\s]*([\d.]*)", "Dropbear SSH", ""),
    (r"SSH-[\d.]+-libssh[_\s]*([\d.]*)", "libssh", ""),
    (r"SSH-[\d.]+-ROSSSH", "RouterOS SSH", "MikroTik"),
    # HTTP Servers
    (r"Apache/([\d.]+)", "Apache httpd", "Apache"),
    (r"nginx/([\d.]+)", "nginx", "nginx"),
    (r"Microsoft-IIS/([\d.]+)", "IIS", "Microsoft"),
    (r"lighttpd/([\d.]+)", "lighttpd", ""),
    (r"LiteSpeed/([\d.]+)", "LiteSpeed", "LiteSpeed Technologies"),
    (r"openresty/([\d.]+)", "OpenResty", ""),
    (r"Caddy", "Caddy", ""),
    (r"Tengine/([\d.]+)", "Tengine", "Alibaba"),
    (r"gunicorn/([\d.]+)", "Gunicorn", ""),
    (r"uvicorn", "Uvicorn", ""),
    # FTP
    (r"vsftpd\s+([\d.]+)", "vsftpd", ""),
    (r"ProFTPD\s+([\d.]+)", "ProFTPD", ""),
    (r"Pure-FTPd", "Pure-FTPd", ""),
    (r"FileZilla Server\s+([\d.]+)", "FileZilla Server", ""),
    (r"Microsoft FTP Service", "Microsoft FTP", "Microsoft"),
    # Mail
    (r"Postfix", "Postfix", ""),
    (r"Exim\s+([\d.]+)", "Exim", ""),
    (r"sendmail[/ ]([\d.]+)", "Sendmail", ""),
    (r"Dovecot", "Dovecot", ""),
    (r"Courier", "Courier", ""),
    (r"Microsoft Exchange", "Exchange", "Microsoft"),
    (r"hMailServer\s+([\d.]+)", "hMailServer", ""),
    # Databases
    (r"mysql[_ ]([\d.]+)", "MySQL", "Oracle"),
    (r"MariaDB-([\d.]+)", "MariaDB", "MariaDB Foundation"),
    (r"PostgreSQL\s+([\d.]+)", "PostgreSQL", "PostgreSQL"),
    (r"redis[_: ]v?([\d.]+)", "Redis", "Redis"),
    (r"MongoDB\s+([\d.]+)", "MongoDB", "MongoDB"),
    (r"Elasticsearch/([\d.]+)", "Elasticsearch", "Elastic"),
    (r"CouchDB/([\d.]+)", "CouchDB", "Apache"),
    # Other services
    (r"BIND\s+([\d.]+)", "BIND", "ISC"),
    (r"dnsmasq-([\d.]+)", "dnsmasq", ""),
    (r"Samba\s+([\d.]+)", "Samba", ""),
    (r"OpenLDAP", "OpenLDAP", ""),
    (r"RabbitMQ\s+([\d.]+)", "RabbitMQ", "VMware"),
    (r"Jetty/([\d.]+)", "Jetty", "Eclipse"),
    (r"Tomcat/([\d.]+)", "Apache Tomcat", "Apache"),
    (r"WildFly/([\d.]+)", "WildFly", "Red Hat"),
    (r"WebLogic\s+Server\s+([\d.]+)", "WebLogic", "Oracle"),
]

# OS detection patterns from banners
OS_PATTERNS: list[tuple[str, str]] = [
    (r"Ubuntu", "Linux (Ubuntu)"),
    (r"Debian", "Linux (Debian)"),
    (r"CentOS", "Linux (CentOS)"),
    (r"Red Hat", "Linux (Red Hat)"),
    (r"Fedora", "Linux (Fedora)"),
    (r"FreeBSD", "FreeBSD"),
    (r"Windows", "Windows"),
    (r"Win32", "Windows"),
    (r"Win64", "Windows"),
    (r"Darwin", "macOS"),
]


def parse_banner(banner: str) -> ServiceInfo:
    """Parse a service banner to extract product and version information.

    Args:
        banner: Raw banner string from a service.

    Returns:
        ServiceInfo dataclass with extracted information.
    """
    if not banner:
        return ServiceInfo(product="unknown", confidence=0.0)

    # Try each version pattern
    for pattern, product, vendor in VERSION_PATTERNS:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex else ""
            os_info = _detect_os(banner)
            cpe = generate_cpe(vendor or product, product, version)

            return ServiceInfo(
                product=product,
                version=version,
                vendor=vendor,
                os=os_info,
                cpe=cpe,
                confidence=0.9 if version else 0.7,
            )

    # Fallback: try to identify service type without specific product
    service_type = identify_service_type(banner)
    return ServiceInfo(
        product=service_type or "unknown",
        confidence=0.4 if service_type else 0.1,
        extra_info=banner[:200],
    )


def extract_version(banner: str) -> Optional[str]:
    """Extract version string from a banner using common patterns.

    Args:
        banner: Raw banner text.

    Returns:
        Version string or None if not found.
    """
    # Generic version patterns (ordered by specificity)
    generic_patterns = [
        r"(?:version|ver|v)[:\s]*([\d]+\.[\d]+\.[\d]+(?:[.-]\w+)?)",
        r"/([\d]+\.[\d]+\.[\d]+(?:[.-]\w+)?)",
        r"\s([\d]+\.[\d]+\.[\d]+)\s",
        r"([\d]+\.[\d]+\.[\d]+(?:p\d+)?)",
        r"([\d]+\.[\d]+)",
    ]

    for pattern in generic_patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def generate_cpe(vendor: str, product: str, version: str = "") -> str:
    """Generate a CPE 2.3 string from service information.

    CPE format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*

    Args:
        vendor: Software vendor name.
        product: Product name.
        version: Version string.

    Returns:
        CPE 2.3 formatted string.
    """
    def _normalize(s: str) -> str:
        """Normalize a string for CPE format."""
        s = s.lower().strip()
        s = re.sub(r"[^a-z0-9._-]", "_", s)
        s = re.sub(r"_+", "_", s)
        return s.strip("_") or "*"

    v = _normalize(vendor)
    p = _normalize(product)
    ver = _normalize(version) if version else "*"

    return f"cpe:2.3:a:{v}:{p}:{ver}:*:*:*:*:*:*:*"


def identify_service_type(banner: str) -> str:
    """Identify the general service type from banner content.

    Args:
        banner: Raw banner text.

    Returns:
        Service type string (e.g., 'http', 'ssh', 'ftp') or empty string.
    """
    banner_lower = banner.lower()

    service_indicators: dict[str, list[str]] = {
        "http": ["http/", "html", "<!doctype", "<html", "content-type:", "server:"],
        "ssh": ["ssh-", "openssh", "dropbear"],
        "ftp": ["220 ", "ftp", "file transfer"],
        "smtp": ["220 ", "smtp", "esmtp", "mail", "postfix", "exim"],
        "pop3": ["+ok", "pop3"],
        "imap": ["* ok", "imap"],
        "mysql": ["mysql", "mariadb"],
        "redis": ["+pong", "-err", "redis"],
        "mongodb": ["mongodb", "mongod", "ismaster"],
        "telnet": ["login:", "username:", "password:"],
        "dns": ["bind", "named", "dns"],
        "ldap": ["ldap", "openldap"],
        "vnc": ["rfb "],
        "rdp": ["\x03\x00\x00"],
    }

    for service, indicators in service_indicators.items():
        for indicator in indicators:
            if indicator in banner_lower:
                return service

    return ""


def _detect_os(banner: str) -> str:
    """Detect OS from banner strings.

    Args:
        banner: Raw banner text.

    Returns:
        OS identification string.
    """
    for pattern, os_name in OS_PATTERNS:
        if re.search(pattern, banner, re.IGNORECASE):
            return os_name
    return ""


def parse_http_server_header(header_value: str) -> ServiceInfo:
    """Parse an HTTP Server header value.

    Args:
        header_value: Value of the Server HTTP header.

    Returns:
        ServiceInfo with extracted details.
    """
    # Common Server header formats: "nginx/1.24.0", "Apache/2.4.57 (Ubuntu)"
    info = parse_banner(header_value)

    # Try to extract OS from parenthetical
    os_match = re.search(r"\(([^)]+)\)", header_value)
    if os_match and not info.os:
        info.os = os_match.group(1)

    return info


def extract_http_headers_info(headers: dict[str, str]) -> dict[str, str]:
    """Extract technology information from HTTP response headers.

    Args:
        headers: Dictionary of HTTP response headers.

    Returns:
        Dictionary of detected technologies and versions.
    """
    tech_info: dict[str, str] = {}

    header_mapping = {
        "server": "web_server",
        "x-powered-by": "framework",
        "x-aspnet-version": "aspnet_version",
        "x-generator": "generator",
        "x-drupal-cache": "cms",
        "x-varnish": "cache",
        "x-cache": "cdn",
        "via": "proxy",
    }

    for header, key in header_mapping.items():
        value = headers.get(header, "") or headers.get(header.title(), "")
        if value:
            tech_info[key] = value

    return tech_info
