"""Recon Phantom Scanner Modules.

This package contains all scanner implementations for the Recon Phantom
reconnaissance framework. Each scanner inherits from BaseScanner and
implements specific reconnaissance functionality.

Available Scanners:
    - PortScanner: TCP/UDP port scanning and service detection
    - SubdomainScanner: Subdomain enumeration and discovery
    - TechFingerprintScanner: Technology stack fingerprinting
    - CVELookupScanner: CVE vulnerability lookup
    - DirectoryBruteforceScanner: Directory and file brute-forcing
    - SSLAnalyzerScanner: SSL/TLS certificate and configuration analysis
    - DNSReconScanner: DNS record enumeration and zone analysis
    - HeaderAnalyzer: HTTP security header analysis and grading
    - WAFDetector: Web Application Firewall detection and fingerprinting
    - GitExposureScanner: Git/sensitive file exposure detection
    - JSAnalyzer: JavaScript file analysis for secrets and endpoints
"""

from recon_phantom.scanners.base import BaseScanner
from recon_phantom.scanners.cve_lookup import CVELookupScanner
from recon_phantom.scanners.directory_bruteforce import DirectoryBruteforceScanner
from recon_phantom.scanners.dns_recon import DNSReconScanner
from recon_phantom.scanners.git_exposure import GitExposureScanner
from recon_phantom.scanners.header_analyzer import HeaderAnalyzer
from recon_phantom.scanners.js_analyzer import JSAnalyzer
from recon_phantom.scanners.port_scanner import PortScanner
from recon_phantom.scanners.ssl_analyzer import SSLAnalyzerScanner
from recon_phantom.scanners.subdomain import SubdomainScanner
from recon_phantom.scanners.tech_fingerprint import TechFingerprintScanner
from recon_phantom.scanners.waf_detector import WAFDetector

# Registry mapping scanner identifiers to their classes.
# Used by the orchestrator to dynamically instantiate scanners by name.
SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    "port_scanner": PortScanner,
    "subdomain": SubdomainScanner,
    "tech_fingerprint": TechFingerprintScanner,
    "cve_lookup": CVELookupScanner,
    "directory_bruteforce": DirectoryBruteforceScanner,
    "ssl_analyzer": SSLAnalyzerScanner,
    "dns_recon": DNSReconScanner,
    "header_analyzer": HeaderAnalyzer,
    "waf_detector": WAFDetector,
    "git_exposure": GitExposureScanner,
    "js_analyzer": JSAnalyzer,
}

__all__ = [
    "BaseScanner",
    "PortScanner",
    "SubdomainScanner",
    "TechFingerprintScanner",
    "CVELookupScanner",
    "DirectoryBruteforceScanner",
    "SSLAnalyzerScanner",
    "DNSReconScanner",
    "HeaderAnalyzer",
    "WAFDetector",
    "GitExposureScanner",
    "JSAnalyzer",
    "SCANNER_REGISTRY",
]
