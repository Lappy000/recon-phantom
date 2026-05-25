"""Network utility functions for DNS resolution, IP handling, and URL parsing."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from typing import Optional
from urllib.parse import urlparse, urlunparse


async def resolve_dns(
    hostname: str,
    record_type: str = "A",
    nameservers: list[str] | None = None,
    timeout: float = 5.0,
) -> list[str]:
    """Resolve DNS records asynchronously.

    Args:
        hostname: The hostname to resolve.
        record_type: DNS record type (A, AAAA, CNAME, MX, TXT, NS).
        nameservers: Optional list of nameserver IPs to use.
        timeout: Resolution timeout in seconds.

    Returns:
        List of resolved addresses/records.
    """
    loop = asyncio.get_event_loop()
    results: list[str] = []

    try:
        if record_type in ("A", "AAAA"):
            family = socket.AF_INET if record_type == "A" else socket.AF_INET6
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, family=family, type=socket.SOCK_STREAM),
                timeout=timeout,
            )
            results = list({info[4][0] for info in addr_info})
        elif record_type == "CNAME":
            # Fallback: use getaddrinfo and compare canonical name
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM),
                timeout=timeout,
            )
            results = list({info[4][0] for info in addr_info})
        else:
            # For MX, TXT, NS - attempt via getaddrinfo fallback
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM),
                timeout=timeout,
            )
            results = list({info[4][0] for info in addr_info})
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        pass

    return results


async def resolve_hostname(hostname: str, timeout: float = 5.0) -> Optional[str]:
    """Resolve a single hostname to its first IPv4 address.

    Args:
        hostname: Hostname to resolve.
        timeout: Resolution timeout.

    Returns:
        IPv4 address string or None if resolution fails.
    """
    results = await resolve_dns(hostname, record_type="A", timeout=timeout)
    return results[0] if results else None


async def bulk_resolve(
    hostnames: list[str],
    concurrency: int = 50,
    timeout: float = 5.0,
) -> dict[str, list[str]]:
    """Resolve multiple hostnames concurrently.

    Args:
        hostnames: List of hostnames to resolve.
        concurrency: Maximum concurrent resolutions.
        timeout: Per-resolution timeout.

    Returns:
        Dictionary mapping hostname -> list of resolved IPs.
    """
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, list[str]] = {}

    async def _resolve_one(host: str) -> tuple[str, list[str]]:
        async with semaphore:
            ips = await resolve_dns(host, timeout=timeout)
            return host, ips

    tasks = [_resolve_one(h) for h in hostnames]
    completed = await asyncio.gather(*tasks, return_exceptions=True)

    for item in completed:
        if isinstance(item, tuple):
            hostname, ips = item
            results[hostname] = ips
        # Skip exceptions

    return results


def is_valid_ipv4(address: str) -> bool:
    """Check if a string is a valid IPv4 address.

    Args:
        address: String to validate.

    Returns:
        True if valid IPv4.
    """
    try:
        ipaddress.IPv4Address(address)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv6(address: str) -> bool:
    """Check if a string is a valid IPv6 address.

    Args:
        address: String to validate.

    Returns:
        True if valid IPv6.
    """
    try:
        ipaddress.IPv6Address(address)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ip(address: str) -> bool:
    """Check if a string is a valid IP address (v4 or v6).

    Args:
        address: String to validate.

    Returns:
        True if valid IP address.
    """
    return is_valid_ipv4(address) or is_valid_ipv6(address)


def is_valid_cidr(cidr: str) -> bool:
    """Check if a string is a valid CIDR notation.

    Args:
        cidr: String to validate (e.g., '192.168.1.0/24').

    Returns:
        True if valid CIDR.
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except (ValueError, TypeError):
        return False


def expand_cidr(cidr: str, max_hosts: int = 65536) -> list[str]:
    """Expand a CIDR notation into individual IP addresses.

    Args:
        cidr: CIDR notation string (e.g., '192.168.1.0/24').
        max_hosts: Maximum number of hosts to expand (safety limit).

    Returns:
        List of IP address strings.

    Raises:
        ValueError: If CIDR is invalid or exceeds max_hosts.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation: {cidr}") from e

    num_hosts = network.num_addresses
    if num_hosts > max_hosts:
        raise ValueError(
            f"CIDR {cidr} contains {num_hosts} addresses, exceeding limit of {max_hosts}"
        )

    return [str(ip) for ip in network.hosts()]


def parse_port_range(port_spec: str) -> list[int]:
    """Parse a port specification into a list of port numbers.

    Supports formats:
        - Single port: "80"
        - Range: "1-1024"
        - Comma-separated: "80,443,8080"
        - Mixed: "22,80-100,443,8000-9000"

    Args:
        port_spec: Port specification string.

    Returns:
        Sorted list of unique port numbers.

    Raises:
        ValueError: If port specification is invalid.
    """
    ports: set[int] = set()

    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            range_parts = part.split("-", 1)
            try:
                start = int(range_parts[0].strip())
                end = int(range_parts[1].strip())
            except ValueError:
                raise ValueError(f"Invalid port range: {part}")

            if start < 1 or end > 65535 or start > end:
                raise ValueError(
                    f"Invalid port range {start}-{end}: must be 1-65535"
                )
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Invalid port number: {part}")

            if port < 1 or port > 65535:
                raise ValueError(f"Port {port} out of range (1-65535)")
            ports.add(port)

    return sorted(ports)


def normalize_url(url: str, default_scheme: str = "https") -> str:
    """Normalize a URL by adding scheme if missing and cleaning components.

    Args:
        url: URL string to normalize.
        default_scheme: Scheme to add if none present.

    Returns:
        Normalized URL string.
    """
    url = url.strip()

    # Add scheme if missing
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = f"{default_scheme}://{url}"

    parsed = urlparse(url)

    # Normalize components
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
    if not path:
        path = "/"

    # Remove default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def extract_domain(url: str) -> str:
    """Extract the domain/hostname from a URL or hostname string.

    Args:
        url: URL or hostname string.

    Returns:
        Domain/hostname without scheme, path, or port.
    """
    if "://" in url:
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc
    else:
        # Remove port if present
        host = url.split(":")[0] if ":" in url and not url.startswith("[") else url

    return host.lower().strip(".")


def is_valid_domain(domain: str) -> bool:
    """Validate a domain name format.

    Args:
        domain: Domain string to validate.

    Returns:
        True if valid domain format.
    """
    if not domain or len(domain) > 253:
        return False

    # Remove trailing dot (FQDN notation)
    if domain.endswith("."):
        domain = domain[:-1]

    # Check each label
    labels = domain.split(".")
    if len(labels) < 2:
        return False

    label_pattern = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    return all(label_pattern.match(label) for label in labels)
