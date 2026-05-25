"""DNS reconnaissance scanner.

Performs comprehensive DNS enumeration including all record types,
zone transfer attempts, SPF/DMARC analysis, DNS cache snooping,
and reverse DNS lookups.
"""

import asyncio
import ipaddress
import re
from typing import Any, Optional

import dns.asyncresolver
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone

from recon_phantom.scanners.base import BaseScanner


# Record types to enumerate
DNS_RECORD_TYPES: list[str] = [
    "A", "AAAA", "MX", "NS", "TXT", "SOA", "SRV", "CNAME", "CAA", "PTR",
]

# Common SRV records to check
SRV_RECORDS: list[str] = [
    "_sip._tcp", "_sip._udp", "_sips._tcp", "_h323cs._tcp",
    "_h323ls._tcp", "_h323rs._tcp", "_imap._tcp", "_imaps._tcp",
    "_pop3._tcp", "_pop3s._tcp", "_smtp._tcp", "_submission._tcp",
    "_xmpp-client._tcp", "_xmpp-server._tcp", "_jabber._tcp",
    "_http._tcp", "_https._tcp", "_caldav._tcp", "_caldavs._tcp",
    "_carddav._tcp", "_carddavs._tcp", "_ldap._tcp", "_ldaps._tcp",
    "_kerberos._tcp", "_kerberos._udp", "_kpasswd._tcp",
    "_kpasswd._udp", "_ntp._udp", "_autodiscover._tcp",
    "_matrix._tcp", "_dmarc._tcp",
]


class DNSReconScanner(BaseScanner):
    """DNS reconnaissance and enumeration scanner.

    Performs comprehensive DNS analysis including:
    - All DNS record type enumeration
    - Zone transfer attempts
    - SPF record analysis
    - DMARC policy analysis
    - DNS cache snooping
    - Reverse DNS lookups
    - SRV record discovery
    """

    @property
    def module_name(self) -> str:
        return "dns_recon"

    def _get_domain(self) -> str:
        """Extract domain from target.

        Returns:
            Clean domain name.
        """
        domain = self.target.lower().strip()
        if "://" in domain:
            domain = domain.split("://", 1)[1]
        domain = domain.split("/")[0]
        domain = domain.split(":")[0]
        return domain

    async def enumerate_records(
        self, domain: str, record_type: str
    ) -> list[dict[str, Any]]:
        """Enumerate DNS records of a specific type.

        Args:
            domain: Domain to query.
            record_type: DNS record type (A, AAAA, MX, etc.).

        Returns:
            List of record dicts with type, name, value, and TTL.
        """
        records: list[dict[str, Any]] = []
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 10.0
            resolver.lifetime = 10.0

            answers = await resolver.resolve(domain, record_type)

            for rdata in answers:
                record = {
                    "type": record_type,
                    "name": domain,
                    "ttl": answers.rrset.ttl,
                    "value": str(rdata),
                }

                # Add priority for MX records
                if record_type == "MX":
                    record["priority"] = rdata.preference
                    record["value"] = str(rdata.exchange)

                # Parse SOA fields
                if record_type == "SOA":
                    record["mname"] = str(rdata.mname)
                    record["rname"] = str(rdata.rname)
                    record["serial"] = rdata.serial
                    record["refresh"] = rdata.refresh
                    record["retry"] = rdata.retry
                    record["expire"] = rdata.expire
                    record["minimum"] = rdata.minimum

                records.append(record)

        except dns.asyncresolver.NXDOMAIN:
            pass
        except dns.asyncresolver.NoAnswer:
            pass
        except dns.asyncresolver.NoNameservers:
            pass
        except dns.exception.Timeout:
            pass
        except Exception:
            pass

        return records

    async def enumerate_srv_records(self, domain: str) -> list[dict[str, Any]]:
        """Enumerate SRV records for common services.

        Args:
            domain: Domain to query SRV records for.

        Returns:
            List of SRV record dicts.
        """
        records: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(20)

        async def check_srv(srv_prefix: str) -> list[dict[str, Any]]:
            async with semaphore:
                fqdn = f"{srv_prefix}.{domain}"
                try:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.timeout = 5.0
                    resolver.lifetime = 5.0
                    answers = await resolver.resolve(fqdn, "SRV")
                    results = []
                    for rdata in answers:
                        results.append({
                            "type": "SRV",
                            "name": fqdn,
                            "ttl": answers.rrset.ttl,
                            "priority": rdata.priority,
                            "weight": rdata.weight,
                            "port": rdata.port,
                            "target": str(rdata.target),
                        })
                    return results
                except (
                    dns.asyncresolver.NXDOMAIN,
                    dns.asyncresolver.NoAnswer,
                    dns.asyncresolver.NoNameservers,
                    dns.exception.Timeout,
                    Exception,
                ):
                    return []

        tasks = [check_srv(srv) for srv in SRV_RECORDS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                records.extend(result)

        return records

    async def attempt_zone_transfer(
        self, domain: str, nameservers: list[str]
    ) -> Optional[dict[str, Any]]:
        """Attempt DNS zone transfer (AXFR) against nameservers.

        Args:
            domain: Domain to attempt transfer for.
            nameservers: List of nameserver hostnames/IPs to try.

        Returns:
            Zone transfer results or None if all fail.
        """
        loop = asyncio.get_event_loop()

        for ns in nameservers:
            try:
                # Resolve NS to IP first
                ns_ip = ns
                try:
                    resolver = dns.asyncresolver.Resolver()
                    answers = await resolver.resolve(ns.rstrip("."), "A")
                    if answers:
                        ns_ip = str(answers[0])
                except Exception:
                    continue

                def _do_axfr() -> Optional[dict[str, Any]]:
                    try:
                        zone_records: list[dict[str, str]] = []
                        z = dns.zone.from_xfr(
                            dns.query.xfr(ns_ip, domain, timeout=10)
                        )
                        for name, node in z.nodes.items():
                            for rdataset in node.rdatasets:
                                for rdata in rdataset:
                                    zone_records.append({
                                        "name": str(name),
                                        "type": dns.rdatatype.to_text(rdataset.rdtype),
                                        "value": str(rdata),
                                        "ttl": str(rdataset.ttl),
                                    })
                        return {
                            "nameserver": ns,
                            "nameserver_ip": ns_ip,
                            "records": zone_records,
                            "record_count": len(zone_records),
                        }
                    except Exception:
                        return None

                result = await loop.run_in_executor(None, _do_axfr)
                if result:
                    return result

            except Exception:
                continue

        return None

    def analyze_spf(self, txt_records: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze SPF records for security issues.

        Args:
            txt_records: List of TXT record dicts.

        Returns:
            SPF analysis results.
        """
        spf_analysis: dict[str, Any] = {
            "exists": False,
            "record": "",
            "mechanisms": [],
            "issues": [],
            "all_qualifier": "",
        }

        for record in txt_records:
            value = record.get("value", "").strip('"')
            if value.startswith("v=spf1"):
                spf_analysis["exists"] = True
                spf_analysis["record"] = value

                # Parse mechanisms
                parts = value.split()
                for part in parts[1:]:  # Skip v=spf1
                    spf_analysis["mechanisms"].append(part)

                    # Check for overly permissive settings
                    if part == "+all":
                        spf_analysis["issues"].append(
                            "SPF uses +all (allows anyone to send email)"
                        )
                        spf_analysis["all_qualifier"] = "+all"
                    elif part == "~all":
                        spf_analysis["all_qualifier"] = "~all"
                    elif part == "-all":
                        spf_analysis["all_qualifier"] = "-all"
                    elif part == "?all":
                        spf_analysis["issues"].append(
                            "SPF uses ?all (neutral, provides no protection)"
                        )
                        spf_analysis["all_qualifier"] = "?all"

                # Check for too many DNS lookups
                lookup_mechanisms = ["include:", "a:", "mx:", "ptr:", "exists:", "redirect="]
                lookup_count = sum(
                    1 for m in spf_analysis["mechanisms"]
                    if any(m.startswith(lm) for lm in lookup_mechanisms)
                )
                if lookup_count > 10:
                    spf_analysis["issues"].append(
                        f"SPF exceeds 10 DNS lookup limit ({lookup_count} lookups)"
                    )

                break

        if not spf_analysis["exists"]:
            spf_analysis["issues"].append("No SPF record found")

        return spf_analysis

    async def analyze_dmarc(self, domain: str) -> dict[str, Any]:
        """Analyze DMARC record for the domain.

        Args:
            domain: Domain to check DMARC for.

        Returns:
            DMARC analysis results.
        """
        dmarc_analysis: dict[str, Any] = {
            "exists": False,
            "record": "",
            "policy": "",
            "subdomain_policy": "",
            "percentage": 100,
            "rua": [],
            "ruf": [],
            "issues": [],
        }

        dmarc_domain = f"_dmarc.{domain}"
        try:
            resolver = dns.asyncresolver.Resolver()
            answers = await resolver.resolve(dmarc_domain, "TXT")

            for rdata in answers:
                value = str(rdata).strip('"')
                if value.startswith("v=DMARC1"):
                    dmarc_analysis["exists"] = True
                    dmarc_analysis["record"] = value

                    # Parse DMARC tags
                    tags = dict(
                        tag.strip().split("=", 1)
                        for tag in value.split(";")
                        if "=" in tag
                    )

                    dmarc_analysis["policy"] = tags.get("p", "")
                    dmarc_analysis["subdomain_policy"] = tags.get("sp", "")

                    if "pct" in tags:
                        try:
                            dmarc_analysis["percentage"] = int(tags["pct"])
                        except ValueError:
                            pass

                    if "rua" in tags:
                        dmarc_analysis["rua"] = tags["rua"].split(",")
                    if "ruf" in tags:
                        dmarc_analysis["ruf"] = tags["ruf"].split(",")

                    # Check for issues
                    if dmarc_analysis["policy"] == "none":
                        dmarc_analysis["issues"].append(
                            "DMARC policy is 'none' (monitoring only, no enforcement)"
                        )
                    if dmarc_analysis["percentage"] < 100:
                        dmarc_analysis["issues"].append(
                            f"DMARC only applies to {dmarc_analysis['percentage']}% of messages"
                        )

                    break

        except (
            dns.asyncresolver.NXDOMAIN,
            dns.asyncresolver.NoAnswer,
            dns.asyncresolver.NoNameservers,
            dns.exception.Timeout,
        ):
            dmarc_analysis["issues"].append("No DMARC record found")

        return dmarc_analysis

    async def reverse_dns(self, ip_addresses: list[str]) -> list[dict[str, str]]:
        """Perform reverse DNS lookups on IP addresses.

        Args:
            ip_addresses: List of IP addresses to reverse-lookup.

        Returns:
            List of reverse DNS result dicts.
        """
        results: list[dict[str, str]] = []
        semaphore = asyncio.Semaphore(20)

        async def reverse_lookup(ip: str) -> Optional[dict[str, str]]:
            async with semaphore:
                try:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.timeout = 5.0
                    rev_name = dns.reversename.from_address(ip)
                    answers = await resolver.resolve(rev_name, "PTR")
                    for rdata in answers:
                        return {"ip": ip, "hostname": str(rdata.target)}
                except Exception:
                    pass
                return None

        tasks = [reverse_lookup(ip) for ip in ip_addresses]
        lookup_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in lookup_results:
            if isinstance(result, dict) and result:
                results.append(result)

        return results

    async def dns_cache_snoop(
        self, domain: str, nameserver: str
    ) -> list[dict[str, Any]]:
        """Attempt DNS cache snooping to discover cached queries.

        Args:
            domain: Domain to check.
            nameserver: Nameserver IP to query.

        Returns:
            List of cached domain results.
        """
        cached: list[dict[str, Any]] = []
        test_domains = [
            f"www.{domain}", f"mail.{domain}", f"api.{domain}",
            f"admin.{domain}", f"dev.{domain}", f"staging.{domain}",
        ]

        loop = asyncio.get_event_loop()

        def _snoop(test_domain: str) -> Optional[dict[str, Any]]:
            try:
                # Non-recursive query (RD=0) to check cache only
                request = dns.message.make_query(test_domain, "A")
                request.flags &= ~dns.flags.RD  # Clear recursion desired flag

                response = dns.query.udp(request, nameserver, timeout=5)

                if response.answer:
                    return {
                        "domain": test_domain,
                        "cached": True,
                        "answers": [str(rr) for rr in response.answer],
                    }
            except Exception:
                pass
            return None

        for test_domain in test_domains:
            result = await loop.run_in_executor(None, _snoop, test_domain)
            if result:
                cached.append(result)

        return cached

    async def run(self) -> list[dict[str, Any]]:
        """Execute DNS reconnaissance.

        Returns:
            List of result dictionaries for DNS findings.
        """
        results: list[dict[str, Any]] = []
        domain = self._get_domain()

        await self.emit_event("dns_recon_started", {"domain": domain})

        # Enumerate all record types
        all_records: dict[str, list[dict[str, Any]]] = {}
        ip_addresses: list[str] = []

        for record_type in DNS_RECORD_TYPES:
            records = await self.enumerate_records(domain, record_type)
            if records:
                all_records[record_type] = records

                # Collect IPs for reverse lookup
                if record_type == "A":
                    ip_addresses.extend(r["value"] for r in records)

        # Enumerate SRV records
        srv_records = await self.enumerate_srv_records(domain)
        if srv_records:
            all_records["SRV"] = srv_records

        # Build record enumeration results
        for rtype, records in all_records.items():
            for record in records:
                result = self.build_result(
                    title=f"DNS {rtype} record: {record.get('value', '')}",
                    description=f"{rtype} record for {domain}: {record.get('value', '')} (TTL: {record.get('ttl', 'N/A')})",
                    severity="info",
                    evidence=str(record),
                    host=domain,
                    protocol="dns",
                    data=record,
                    confidence=1.0,
                )
                results.append(result)

        # Zone transfer attempt
        nameservers = [r["value"] for r in all_records.get("NS", [])]
        if nameservers:
            zone_result = await self.attempt_zone_transfer(domain, nameservers)
            if zone_result:
                results.append(self.build_result(
                    title="DNS zone transfer successful (AXFR)",
                    description=(
                        f"Zone transfer allowed on {zone_result['nameserver']} "
                        f"({zone_result['record_count']} records leaked)"
                    ),
                    severity="critical",
                    evidence=f"AXFR from {zone_result['nameserver']}",
                    host=domain,
                    protocol="dns",
                    data=zone_result,
                    confidence=1.0,
                ))

        # SPF analysis
        txt_records = all_records.get("TXT", [])
        spf_analysis = self.analyze_spf(txt_records)
        if spf_analysis["issues"]:
            severity = "medium" if "+all" in str(spf_analysis.get("all_qualifier", "")) else "low"
            if not spf_analysis["exists"]:
                severity = "medium"
            results.append(self.build_result(
                title="SPF configuration issues",
                description="; ".join(spf_analysis["issues"]),
                severity=severity,
                evidence=spf_analysis.get("record", "No SPF record"),
                host=domain,
                protocol="dns",
                data=spf_analysis,
                confidence=0.95,
            ))

        # DMARC analysis
        dmarc_analysis = await self.analyze_dmarc(domain)
        if dmarc_analysis["issues"]:
            severity = "medium" if not dmarc_analysis["exists"] else "low"
            results.append(self.build_result(
                title="DMARC configuration issues",
                description="; ".join(dmarc_analysis["issues"]),
                severity=severity,
                evidence=dmarc_analysis.get("record", "No DMARC record"),
                host=domain,
                protocol="dns",
                data=dmarc_analysis,
                confidence=0.95,
            ))

        # Reverse DNS
        if ip_addresses:
            rdns_results = await self.reverse_dns(ip_addresses[:20])
            for rdns in rdns_results:
                results.append(self.build_result(
                    title=f"Reverse DNS: {rdns['ip']} -> {rdns['hostname']}",
                    description=f"IP {rdns['ip']} resolves to {rdns['hostname']}",
                    severity="info",
                    evidence=f"PTR {rdns['ip']} = {rdns['hostname']}",
                    host=domain,
                    protocol="dns",
                    data=rdns,
                    confidence=1.0,
                ))

        # DNS cache snooping (if we have a nameserver IP)
        if nameservers and self.config.get("cache_snoop", False):
            ns_ip = ""
            try:
                resolver = dns.asyncresolver.Resolver()
                answers = await resolver.resolve(nameservers[0].rstrip("."), "A")
                if answers:
                    ns_ip = str(answers[0])
            except Exception:
                pass

            if ns_ip:
                cached = await self.dns_cache_snoop(domain, ns_ip)
                for item in cached:
                    results.append(self.build_result(
                        title=f"DNS cache snooping: {item['domain']} cached",
                        description=f"Domain {item['domain']} found in DNS cache",
                        severity="low",
                        evidence=str(item["answers"]),
                        host=domain,
                        protocol="dns",
                        data=item,
                        confidence=0.8,
                    ))

        await self.emit_event("dns_recon_completed", {
            "records_found": len(results),
        })

        return results
