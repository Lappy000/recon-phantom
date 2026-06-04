"""Subdomain enumeration scanner.

Discovers subdomains through DNS brute-forcing with built-in wordlists,
Certificate Transparency log queries (crt.sh), and permutation generation.
Validates discovered subdomains via DNS resolution.
"""

import asyncio
import re
from typing import Any, Optional

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import httpx

from recon_phantom.scanners.base import BaseScanner


# Built-in subdomain wordlist (common subdomains)
SUBDOMAIN_WORDLIST: list[str] = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "remote", "blog",
    "webdisk", "server", "ns", "cpanel", "whm", "autodiscover", "autoconfig",
    "m", "imap", "test", "old", "new", "mobile", "api", "dev", "staging",
    "stage", "app", "admin", "portal", "web", "vpn", "cloud", "git", "svn",
    "shop", "store", "secure", "beta", "demo", "docs", "help", "support",
    "forum", "wiki", "community", "cdn", "static", "assets", "media", "img",
    "images", "video", "download", "downloads", "files", "backup", "db",
    "database", "mysql", "postgres", "redis", "elastic", "search", "monitor",
    "monitoring", "status", "health", "grafana", "prometheus", "kibana",
    "jenkins", "ci", "cd", "build", "deploy", "release", "production", "prod",
    "development", "qa", "uat", "sandbox", "lab", "internal", "intranet",
    "extranet", "partner", "partners", "client", "clients", "customer",
    "crm", "erp", "hr", "finance", "accounting", "billing", "payment",
    "pay", "checkout", "cart", "order", "orders", "invoice", "ticket",
    "tickets", "jira", "confluence", "slack", "teams", "chat", "messaging",
    "email", "exchange", "outlook", "calendar", "contacts", "drive",
    "storage", "s3", "bucket", "archive", "log", "logs", "analytics",
    "tracking", "metrics", "report", "reports", "dashboard", "panel",
    "control", "manager", "console", "auth", "login", "sso", "oauth",
    "identity", "id", "accounts", "account", "signup", "register",
    "password", "reset", "verify", "activate", "proxy", "gateway",
    "lb", "loadbalancer", "haproxy", "nginx", "apache", "iis", "tomcat",
    "node", "nodejs", "python", "django", "flask", "rails", "ruby",
    "java", "spring", "go", "rust", "docker", "k8s", "kubernetes",
    "swarm", "cluster", "master", "slave", "worker", "agent", "runner",
    "service", "services", "microservice", "lambda", "function", "edge",
    "global", "us", "eu", "asia", "east", "west", "north", "south",
    "us-east", "us-west", "eu-west", "eu-central", "ap-southeast",
    "staging1", "staging2", "dev1", "dev2", "test1", "test2", "owa",
    "exchange2", "mail2", "smtp2", "pop3", "imap2", "relay", "mailgw",
    "postfix", "mx3", "ns5", "dns3", "vpn2", "ssl", "sftp", "ssh",
    "rdp", "citrix", "terminal", "ts", "rds", "vdi", "workspace",
    "office", "sharepoint", "onedrive", "teams2", "skype", "lync",
    "sip", "voip", "pbx", "phone", "fax", "printer", "scan", "ntp",
    "time", "snmp", "trap", "syslog", "radius", "tacacs", "ldap", "ad",
    "dc", "dc1", "dc2", "pdc", "bdc", "gw", "fw", "firewall", "ids",
    "ips", "waf", "dmz", "bastion", "jump", "jumpbox", "management",
]

# Common permutation prefixes and suffixes
PERMUTATION_PREFIXES: list[str] = [
    "dev-", "staging-", "test-", "prod-", "api-", "admin-", "internal-",
    "new-", "old-", "v2-", "beta-", "alpha-", "pre-",
]

PERMUTATION_SUFFIXES: list[str] = [
    "-dev", "-staging", "-test", "-prod", "-api", "-admin", "-internal",
    "-new", "-old", "-v2", "-beta", "-backup", "-temp",
]


class SubdomainScanner(BaseScanner):
    """Subdomain enumeration through DNS brute-force, CT logs, and permutations.

    Discovers subdomains using multiple techniques:
    1. DNS brute-force with built-in wordlist
    2. Certificate Transparency log queries via crt.sh
    3. Permutation generation from discovered subdomains
    4. DNS validation of all candidates
    """

    @property
    def module_name(self) -> str:
        return "subdomain"

    def _get_base_domain(self) -> str:
        """Extract the base domain from target.

        Returns:
            Base domain string (e.g., 'example.com').
        """
        target = self.target.lower().strip()
        # Remove protocol if present
        if "://" in target:
            target = target.split("://", 1)[1]
        # Remove path
        target = target.split("/")[0]
        # Remove port
        target = target.split(":")[0]
        return target

    async def dns_brute_force(self, domain: str) -> set[str]:
        """Brute-force subdomains using the built-in wordlist.

        Args:
            domain: Base domain to enumerate subdomains for.

        Returns:
            Set of discovered subdomain FQDNs.
        """
        discovered: set[str] = set()
        wordlist = self.config.get("wordlist", SUBDOMAIN_WORDLIST)
        semaphore = self.get_semaphore()

        async def check_subdomain(subdomain: str) -> Optional[str]:
            async with semaphore:
                fqdn = f"{subdomain}.{domain}"
                try:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.timeout = 5.0
                    resolver.lifetime = 5.0
                    answers = await resolver.resolve(fqdn, "A")
                    if answers:
                        return fqdn
                except (
                    dns.asyncresolver.NXDOMAIN,
                    dns.asyncresolver.NoAnswer,
                    dns.asyncresolver.NoNameservers,
                    dns.exception.Timeout,
                    dns.name.EmptyLabel,
                    Exception,
                ):
                    pass
                return None

        # Run DNS queries concurrently
        tasks = [check_subdomain(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, str) and result:
                discovered.add(result)

        return discovered

    async def query_certificate_transparency(self, domain: str) -> set[str]:
        """Query Certificate Transparency logs via crt.sh API.

        Args:
            domain: Domain to search CT logs for.

        Returns:
            Set of subdomains found in CT logs.
        """
        discovered: set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            client = await self.get_http_client()
            response = await client.get(
                url,
                headers=self.get_stealth_headers(),
                timeout=30.0,
            )

            if response.status_code == 200:
                try:
                    entries = response.json()
                    for entry in entries:
                        name_value = entry.get("name_value", "")
                        # Split multi-line entries
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            # Remove wildcard prefix
                            if name.startswith("*."):
                                name = name[2:]
                            if name.endswith(domain) and self._is_valid_subdomain(name):
                                discovered.add(name)
                except (ValueError, KeyError):
                    pass
        except (httpx.HTTPError, httpx.TimeoutException):
            await self.emit_event("ct_query_failed", {"domain": domain})

        return discovered

    async def generate_permutations(
        self, domain: str, known_subdomains: set[str]
    ) -> set[str]:
        """Generate subdomain permutations from known subdomains.

        Args:
            domain: Base domain.
            known_subdomains: Set of already-discovered subdomains.

        Returns:
            Set of permutation candidates.
        """
        permutations: set[str] = set()

        for fqdn in known_subdomains:
            # Extract the subdomain part
            sub_part = fqdn.replace(f".{domain}", "")
            if not sub_part or sub_part == domain:
                continue

            # Add prefixes
            for prefix in PERMUTATION_PREFIXES:
                candidate = f"{prefix}{sub_part}.{domain}"
                permutations.add(candidate)

            # Add suffixes
            for suffix in PERMUTATION_SUFFIXES:
                candidate = f"{sub_part}{suffix}.{domain}"
                permutations.add(candidate)

            # Number permutations
            for i in range(1, 4):
                permutations.add(f"{sub_part}{i}.{domain}")
                permutations.add(f"{sub_part}-{i}.{domain}")

        # Remove already known subdomains
        permutations -= known_subdomains

        return permutations

    async def validate_subdomains(self, subdomains: set[str]) -> list[dict[str, Any]]:
        """Validate subdomain candidates via DNS resolution.

        Args:
            subdomains: Set of subdomain FQDNs to validate.

        Returns:
            List of validated subdomain info dicts.
        """
        validated: list[dict[str, Any]] = []
        semaphore = self.get_semaphore()

        async def resolve_subdomain(fqdn: str) -> Optional[dict[str, Any]]:
            async with semaphore:
                try:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.timeout = 5.0
                    resolver.lifetime = 5.0

                    ip_addresses: list[str] = []
                    cnames: list[str] = []

                    # Try A record
                    try:
                        answers = await resolver.resolve(fqdn, "A")
                        ip_addresses = [str(rdata) for rdata in answers]
                    except (dns.asyncresolver.NoAnswer, dns.asyncresolver.NXDOMAIN):
                        pass

                    # Try AAAA record
                    try:
                        answers = await resolver.resolve(fqdn, "AAAA")
                        ip_addresses.extend([str(rdata) for rdata in answers])
                    except (dns.asyncresolver.NoAnswer, dns.asyncresolver.NXDOMAIN):
                        pass

                    # Try CNAME record
                    try:
                        answers = await resolver.resolve(fqdn, "CNAME")
                        cnames = [str(rdata.target) for rdata in answers]
                    except (dns.asyncresolver.NoAnswer, dns.asyncresolver.NXDOMAIN):
                        pass

                    if ip_addresses or cnames:
                        return {
                            "subdomain": fqdn,
                            "ip_addresses": ip_addresses,
                            "cnames": cnames,
                        }
                except (
                    dns.exception.Timeout,
                    dns.asyncresolver.NoNameservers,
                    Exception,
                ):
                    pass
                return None

        tasks = [resolve_subdomain(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result:
                validated.append(result)

        return validated

    def _is_valid_subdomain(self, name: str) -> bool:
        """Check if a string is a valid subdomain format.

        Args:
            name: Candidate subdomain string.

        Returns:
            True if valid subdomain format.
        """
        if not name or len(name) > 253:
            return False
        # Must contain only valid characters
        pattern = r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$"
        return bool(re.match(pattern, name))

    async def run(self) -> list[dict[str, Any]]:
        """Execute subdomain enumeration.

        Returns:
            List of result dictionaries for discovered subdomains.
        """
        results: list[dict[str, Any]] = []
        domain = self._get_base_domain()

        await self.emit_event("subdomain_scan_started", {"domain": domain})

        # Phase 1: DNS brute force
        brute_results = await self.dns_brute_force(domain)
        await self.emit_event("brute_force_complete", {
            "found": len(brute_results),
        })

        # Phase 2: Certificate Transparency
        ct_results = await self.query_certificate_transparency(domain)
        await self.emit_event("ct_query_complete", {
            "found": len(ct_results),
        })

        # Combine results
        all_subdomains = brute_results | ct_results

        # Phase 3: Permutation generation
        if self.config.get("permutations", True):
            permutations = await self.generate_permutations(domain, all_subdomains)
            # Validate permutations
            perm_validated = await self.validate_subdomains(permutations)
            for item in perm_validated:
                all_subdomains.add(item["subdomain"])

        # Phase 4: Final validation of all discovered subdomains
        validated = await self.validate_subdomains(all_subdomains)

        # Build results
        for sub_info in validated:
            fqdn = sub_info["subdomain"]
            ips = sub_info["ip_addresses"]
            cnames = sub_info["cnames"]

            # Detect potential takeover (CNAME to non-resolving domains)
            takeover_risk = False
            if cnames:
                for cname in cnames:
                    # Check common takeover-vulnerable services
                    vuln_patterns = [
                        "herokuapp.com", "s3.amazonaws.com", "cloudfront.net",
                        "azurewebsites.net", "github.io", "shopify.com",
                        "fastly.net", "pantheon.io", "zendesk.com",
                        "wordpress.com", "ghost.io", "surge.sh",
                        "bitbucket.io", "netlify.app", "fly.dev",
                    ]
                    if any(p in cname for p in vuln_patterns):
                        takeover_risk = True
                        break

            severity = "info"
            if takeover_risk:
                severity = "high"

            result = self.build_result(
                title=f"Subdomain discovered: {fqdn}",
                description=(
                    f"Subdomain {fqdn} resolves to {', '.join(ips) if ips else 'CNAME: ' + ', '.join(cnames)}"
                    + (" [POTENTIAL TAKEOVER]" if takeover_risk else "")
                ),
                severity=severity,
                evidence=f"A: {ips}, CNAME: {cnames}",
                host=fqdn,
                protocol="dns",
                data={
                    "subdomain": fqdn,
                    "ip_addresses": ips,
                    "cnames": cnames,
                    "takeover_risk": takeover_risk,
                    "source": "brute_force" if fqdn in brute_results else "ct_logs",
                },
                confidence=0.95,
            )
            results.append(result)

        await self.emit_event("subdomain_scan_completed", {
            "total_found": len(results),
        })

        return results
