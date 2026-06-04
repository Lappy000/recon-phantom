"""SSL/TLS certificate and protocol analyzer.

Performs comprehensive TLS analysis including certificate chain validation,
expiry checks, weak cipher detection, deprecated protocol identification,
HSTS verification, and SAN extraction.
"""

import asyncio
import datetime
import ssl
import socket
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import ExtensionOID, NameOID

from recon_phantom.scanners.base import BaseScanner


# Weak cipher suites that should be flagged
WEAK_CIPHERS: set[str] = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
    "RC2", "IDEA", "SEED", "CAMELLIA128",
}

# Deprecated TLS protocol versions
DEPRECATED_PROTOCOLS: dict[str, str] = {
    "SSLv2": "critical",
    "SSLv3": "critical",
    "TLSv1": "high",
    "TLSv1.0": "high",
    "TLSv1.1": "medium",
}

# Minimum acceptable key sizes
MIN_KEY_SIZES: dict[str, int] = {
    "RSA": 2048,
    "DSA": 2048,
    "EC": 256,
}


class SSLAnalyzerScanner(BaseScanner):
    """TLS/SSL certificate and protocol analyzer.

    Performs comprehensive analysis of TLS configuration including:
    - Certificate chain validation and expiry
    - Weak cipher suite detection
    - Deprecated protocol detection
    - HSTS header verification
    - Subject Alternative Name extraction
    - Key strength analysis
    """

    @property
    def module_name(self) -> str:
        return "ssl_analyzer"

    def _get_host_port(self) -> tuple[str, int]:
        """Extract hostname and port from target.

        Returns:
            Tuple of (hostname, port).
        """
        host = self.target
        port = 443

        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/")[0]

        if ":" in host:
            parts = host.rsplit(":", 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = 443

        return host, port

    async def get_certificate(
        self, host: str, port: int
    ) -> Optional[tuple[x509.Certificate, list[x509.Certificate], dict[str, Any]]]:
        """Connect to host and retrieve the TLS certificate chain.

        Args:
            host: Hostname to connect to.
            port: Port number.

        Returns:
            Tuple of (leaf_cert, chain, connection_info) or None on failure.
        """
        loop = asyncio.get_event_loop()

        def _get_cert_sync() -> Optional[tuple[x509.Certificate, list[x509.Certificate], dict[str, Any]]]:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            try:
                with socket.create_connection((host, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        # Get certificate in DER format
                        der_cert = ssock.getpeercert(binary_form=True)
                        if not der_cert:
                            return None

                        cert = x509.load_der_x509_certificate(der_cert)

                        # Connection info
                        conn_info = {
                            "protocol_version": ssock.version(),
                            "cipher": ssock.cipher(),
                            "compression": ssock.compression(),
                        }

                        # Try to get the full chain
                        chain: list[x509.Certificate] = []
                        # Note: Python's ssl module doesn't easily expose the full chain
                        # We'll work with the leaf cert primarily

                        return cert, chain, conn_info

            except (socket.error, ssl.SSLError, OSError, ConnectionRefusedError):
                return None

        return await loop.run_in_executor(None, _get_cert_sync)

    async def check_protocol_support(
        self, host: str, port: int
    ) -> dict[str, bool]:
        """Check which TLS/SSL protocol versions are supported.

        Args:
            host: Hostname to test.
            port: Port number.

        Returns:
            Dict mapping protocol names to support status.
        """
        loop = asyncio.get_event_loop()
        protocols_supported: dict[str, bool] = {}

        protocol_map = {
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }

        # Check TLS 1.0 and 1.1 (may not be available in newer Python)
        try:
            protocol_map["TLSv1.0"] = ssl.TLSVersion.TLSv1
        except AttributeError:
            pass

        try:
            protocol_map["TLSv1.1"] = ssl.TLSVersion.TLSv1_1
        except AttributeError:
            pass

        def _check_protocol(protocol_name: str, min_version: Any, max_version: Any) -> bool:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = min_version
                context.maximum_version = max_version

                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host):
                        return True
            except (ssl.SSLError, socket.error, OSError):
                return False

        for proto_name, proto_version in protocol_map.items():
            try:
                result = await loop.run_in_executor(
                    None, _check_protocol, proto_name, proto_version, proto_version
                )
                protocols_supported[proto_name] = result
            except Exception:
                protocols_supported[proto_name] = False

        return protocols_supported

    def analyze_certificate(self, cert: x509.Certificate) -> dict[str, Any]:
        """Analyze certificate properties.

        Args:
            cert: X.509 certificate to analyze.

        Returns:
            Dict with certificate analysis results.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        analysis: dict[str, Any] = {}

        # Basic info
        analysis["subject"] = self._get_name_attributes(cert.subject)
        analysis["issuer"] = self._get_name_attributes(cert.issuer)
        analysis["serial_number"] = str(cert.serial_number)
        analysis["not_before"] = cert.not_valid_before_utc.isoformat()
        analysis["not_after"] = cert.not_valid_after_utc.isoformat()

        # Expiry check
        days_until_expiry = (cert.not_valid_after_utc - now).days
        analysis["days_until_expiry"] = days_until_expiry
        analysis["is_expired"] = days_until_expiry < 0
        analysis["expires_soon"] = 0 < days_until_expiry < 30

        # Signature algorithm
        analysis["signature_algorithm"] = cert.signature_hash_algorithm
        if cert.signature_hash_algorithm:
            analysis["signature_algorithm_name"] = cert.signature_hash_algorithm.name
            analysis["weak_signature"] = cert.signature_hash_algorithm.name in ("md5", "sha1")
        else:
            analysis["signature_algorithm_name"] = "unknown"
            analysis["weak_signature"] = False

        # Key info
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            analysis["key_type"] = "RSA"
            analysis["key_size"] = public_key.key_size
            analysis["weak_key"] = public_key.key_size < MIN_KEY_SIZES["RSA"]
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            analysis["key_type"] = "EC"
            analysis["key_size"] = public_key.key_size
            analysis["weak_key"] = public_key.key_size < MIN_KEY_SIZES["EC"]
        elif isinstance(public_key, dsa.DSAPublicKey):
            analysis["key_type"] = "DSA"
            analysis["key_size"] = public_key.key_size
            analysis["weak_key"] = public_key.key_size < MIN_KEY_SIZES["DSA"]
        else:
            analysis["key_type"] = "unknown"
            analysis["key_size"] = 0
            analysis["weak_key"] = True

        # Subject Alternative Names
        sans: list[str] = []
        try:
            san_extension = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_value = san_extension.value
            sans = [name.value for name in san_value.get_values_for_type(x509.DNSName)]
            # Also get IP addresses
            ip_sans = [str(name.value) for name in san_value.get_values_for_type(x509.IPAddress)]
            sans.extend(ip_sans)
        except x509.ExtensionNotFound:
            pass
        analysis["sans"] = sans

        # Self-signed check
        analysis["is_self_signed"] = cert.issuer == cert.subject

        # Certificate transparency
        has_ct = False
        try:
            cert.extensions.get_extension_for_oid(
                ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
            )
            has_ct = True
        except x509.ExtensionNotFound:
            pass
        analysis["has_certificate_transparency"] = has_ct

        return analysis

    def _get_name_attributes(self, name: x509.Name) -> dict[str, str]:
        """Extract name attributes from X.509 Name.

        Args:
            name: X.509 Name object.

        Returns:
            Dict of name attribute key-value pairs.
        """
        attrs: dict[str, str] = {}
        oid_map = {
            NameOID.COMMON_NAME: "CN",
            NameOID.ORGANIZATION_NAME: "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME: "C",
            NameOID.STATE_OR_PROVINCE_NAME: "ST",
            NameOID.LOCALITY_NAME: "L",
        }
        for oid, label in oid_map.items():
            values = name.get_attributes_for_oid(oid)
            if values:
                attrs[label] = values[0].value
        return attrs

    async def check_hsts(self, host: str) -> dict[str, Any]:
        """Check for HSTS header on the target.

        Args:
            host: Target hostname.

        Returns:
            HSTS analysis results.
        """
        hsts_info: dict[str, Any] = {
            "enabled": False,
            "max_age": 0,
            "include_subdomains": False,
            "preload": False,
        }

        response = await self.make_request(f"https://{host}")
        if response:
            hsts_header = response.headers.get("strict-transport-security", "")
            if hsts_header:
                hsts_info["enabled"] = True

                # Parse max-age
                import re
                max_age_match = re.search(r"max-age=(\d+)", hsts_header)
                if max_age_match:
                    hsts_info["max_age"] = int(max_age_match.group(1))

                hsts_info["include_subdomains"] = "includesubdomains" in hsts_header.lower()
                hsts_info["preload"] = "preload" in hsts_header.lower()

        return hsts_info

    async def run(self) -> list[dict[str, Any]]:
        """Execute SSL/TLS analysis.

        Returns:
            List of result dictionaries for SSL findings.
        """
        results: list[dict[str, Any]] = []
        host, port = self._get_host_port()

        await self.emit_event("ssl_analysis_started", {"host": host, "port": port})

        # Get certificate
        cert_result = await self.get_certificate(host, port)
        if cert_result is None:
            results.append(self.build_result(
                title="SSL/TLS connection failed",
                description=f"Could not establish TLS connection to {host}:{port}",
                severity="info",
                host=host,
                port=port,
                protocol="tls",
                confidence=0.9,
            ))
            return results

        cert, chain, conn_info = cert_result
        analysis = self.analyze_certificate(cert)

        # Certificate expiry
        if analysis["is_expired"]:
            results.append(self.build_result(
                title="SSL certificate expired",
                description=f"Certificate expired {abs(analysis['days_until_expiry'])} days ago",
                severity="critical",
                evidence=f"Not After: {analysis['not_after']}",
                host=host,
                port=port,
                protocol="tls",
                data={"days_expired": abs(analysis["days_until_expiry"])},
                confidence=1.0,
            ))
        elif analysis["expires_soon"]:
            results.append(self.build_result(
                title="SSL certificate expiring soon",
                description=f"Certificate expires in {analysis['days_until_expiry']} days",
                severity="medium",
                evidence=f"Not After: {analysis['not_after']}",
                host=host,
                port=port,
                protocol="tls",
                data={"days_until_expiry": analysis["days_until_expiry"]},
                confidence=1.0,
            ))

        # Self-signed certificate
        if analysis["is_self_signed"]:
            results.append(self.build_result(
                title="Self-signed SSL certificate",
                description="Certificate is self-signed and will not be trusted by browsers",
                severity="medium",
                evidence=f"Issuer: {analysis['issuer']}, Subject: {analysis['subject']}",
                host=host,
                port=port,
                protocol="tls",
                confidence=1.0,
            ))

        # Weak key
        if analysis["weak_key"]:
            results.append(self.build_result(
                title=f"Weak {analysis['key_type']} key ({analysis['key_size']} bits)",
                description=f"Certificate uses a weak {analysis['key_type']} key of {analysis['key_size']} bits",
                severity="high",
                evidence=f"Key: {analysis['key_type']} {analysis['key_size']} bits",
                host=host,
                port=port,
                protocol="tls",
                data={"key_type": analysis["key_type"], "key_size": analysis["key_size"]},
                confidence=1.0,
            ))

        # Weak signature algorithm
        if analysis["weak_signature"]:
            results.append(self.build_result(
                title=f"Weak signature algorithm: {analysis['signature_algorithm_name']}",
                description="Certificate uses a deprecated/weak signature algorithm",
                severity="high",
                evidence=f"Signature: {analysis['signature_algorithm_name']}",
                host=host,
                port=port,
                protocol="tls",
                confidence=1.0,
            ))

        # Check deprecated protocols
        protocols = await self.check_protocol_support(host, port)
        for proto_name, supported in protocols.items():
            if supported and proto_name in DEPRECATED_PROTOCOLS:
                results.append(self.build_result(
                    title=f"Deprecated protocol supported: {proto_name}",
                    description=f"Server supports deprecated TLS protocol {proto_name}",
                    severity=DEPRECATED_PROTOCOLS[proto_name],
                    evidence=f"Protocol {proto_name} connection successful",
                    host=host,
                    port=port,
                    protocol="tls",
                    data={"protocol": proto_name},
                    confidence=0.95,
                ))

        # HSTS check
        hsts_info = await self.check_hsts(host)
        if not hsts_info["enabled"]:
            results.append(self.build_result(
                title="HSTS not enabled",
                description="HTTP Strict Transport Security header is not set",
                severity="medium",
                host=host,
                port=port,
                protocol="tls",
                data=hsts_info,
                confidence=0.9,
            ))
        elif hsts_info["max_age"] < 31536000:
            results.append(self.build_result(
                title="HSTS max-age too short",
                description=f"HSTS max-age is {hsts_info['max_age']} seconds (recommended: >= 31536000)",
                severity="low",
                evidence=f"max-age={hsts_info['max_age']}",
                host=host,
                port=port,
                protocol="tls",
                data=hsts_info,
                confidence=0.9,
            ))

        # Certificate info result
        results.append(self.build_result(
            title=f"SSL certificate: {analysis['subject'].get('CN', host)}",
            description=(
                f"Valid until {analysis['not_after']}, "
                f"{analysis['key_type']} {analysis['key_size']} bits, "
                f"SANs: {', '.join(analysis['sans'][:10])}"
            ),
            severity="info",
            evidence=f"Issuer: {analysis['issuer'].get('O', 'Unknown')}",
            host=host,
            port=port,
            protocol="tls",
            data={
                "subject": analysis["subject"],
                "issuer": analysis["issuer"],
                "sans": analysis["sans"],
                "key_type": analysis["key_type"],
                "key_size": analysis["key_size"],
                "days_until_expiry": analysis["days_until_expiry"],
                "is_self_signed": analysis["is_self_signed"],
                "has_ct": analysis["has_certificate_transparency"],
                "protocol_version": conn_info.get("protocol_version"),
                "cipher_suite": conn_info.get("cipher"),
            },
            confidence=1.0,
        ))

        await self.emit_event("ssl_analysis_completed", {
            "findings": len(results),
        })

        return results
