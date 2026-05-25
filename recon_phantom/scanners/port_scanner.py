"""Async TCP port scanner with banner grabbing and service fingerprinting.

Scans top 1000 common ports using asyncio TCP connections with configurable
concurrency. Performs banner grabbing and matches against known service patterns.
"""

import asyncio
import re
import socket
from typing import Any, Optional

from recon_phantom.scanners.base import BaseScanner


# Top 1000 most common ports (condensed to key services + common ranges)
TOP_PORTS: list[int] = [
    20, 21, 22, 23, 25, 26, 37, 43, 49, 53, 67, 68, 69, 79, 80, 81, 88,
    110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 194,
    199, 201, 209, 220, 264, 311, 389, 443, 444, 445, 464, 465, 497, 500,
    502, 512, 513, 514, 515, 520, 521, 523, 530, 540, 548, 554, 563, 587,
    591, 593, 623, 625, 631, 636, 639, 641, 646, 647, 648, 666, 667, 668,
    683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783,
    787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911,
    912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1010, 1023, 1024,
    1025, 1026, 1027, 1028, 1029, 1030, 1033, 1034, 1035, 1036, 1038, 1058,
    1059, 1080, 1083, 1099, 1100, 1110, 1111, 1119, 1131, 1194, 1220, 1234,
    1241, 1270, 1311, 1337, 1344, 1352, 1433, 1434, 1443, 1494, 1500, 1501,
    1503, 1521, 1524, 1526, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658,
    1666, 1687, 1688, 1700, 1717, 1718, 1720, 1723, 1755, 1761, 1782, 1783,
    1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935,
    1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
    2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033,
    2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049,
    2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126,
    2135, 2144, 2160, 2161, 2170, 2179, 2190, 2196, 2200, 2222, 2251, 2260,
    2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492,
    2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701,
    2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910,
    2920, 2967, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017,
    3030, 3031, 3050, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261,
    3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351,
    3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527,
    3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801,
    3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905,
    3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003,
    4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321,
    4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900,
    4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054,
    5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221,
    5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440,
    5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679,
    5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859,
    5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915,
    5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989,
    5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025,
    6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510,
    6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689,
    6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001,
    7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402,
    7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911,
    7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010,
    8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193,
    8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402,
    8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899,
    8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080,
    9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207,
    9220, 9290, 9415, 9418, 9443, 9485, 9500, 9502, 9503, 9535, 9575, 9593,
    9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943,
    9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010,
    10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617,
    10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174,
    12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442,
    15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016,
    16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988,
    19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031,
    20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735,
    26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718,
    30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774,
    32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784,
    33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511,
    42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154,
    49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167,
    49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300,
    50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869,
    54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797,
    58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000,
    65129, 65389,
]

# Service fingerprint patterns (regex patterns matched against banners)
SERVICE_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "ssh": [
        (r"SSH-[\d.]+-(.+)", "SSH"),
        (r"OpenSSH[_\s]+([\d.]+)", "OpenSSH"),
        (r"dropbear", "Dropbear SSH"),
    ],
    "http": [
        (r"HTTP/[\d.]+\s+\d+", "HTTP"),
        (r"Apache/([\d.]+)", "Apache"),
        (r"nginx/([\d.]+)", "nginx"),
        (r"Microsoft-IIS/([\d.]+)", "IIS"),
        (r"lighttpd/([\d.]+)", "lighttpd"),
    ],
    "ftp": [
        (r"220.*FTP", "FTP"),
        (r"vsftpd\s+([\d.]+)", "vsftpd"),
        (r"ProFTPD\s+([\d.]+)", "ProFTPD"),
        (r"Pure-FTPd", "Pure-FTPd"),
        (r"FileZilla Server", "FileZilla FTP"),
    ],
    "smtp": [
        (r"220.*SMTP", "SMTP"),
        (r"220.*Postfix", "Postfix"),
        (r"220.*Exim", "Exim"),
        (r"220.*sendmail", "Sendmail"),
        (r"Microsoft ESMTP MAIL", "Microsoft Exchange"),
    ],
    "mysql": [
        (r"mysql", "MySQL"),
        (r"MariaDB", "MariaDB"),
        (r"[\x00-\x09].*mysql_native_password", "MySQL"),
    ],
    "redis": [
        (r"-ERR.*redis", "Redis"),
        (r"\+PONG", "Redis"),
        (r"redis_version:([\d.]+)", "Redis"),
    ],
    "mongodb": [
        (r"MongoDB", "MongoDB"),
        (r"mongod", "MongoDB"),
    ],
    "postgresql": [
        (r"PostgreSQL", "PostgreSQL"),
    ],
    "telnet": [
        (r"\xff[\xfb\xfd\xfe]", "Telnet"),
        (r"login:", "Telnet"),
    ],
    "pop3": [
        (r"\+OK.*POP3", "POP3"),
        (r"\+OK Dovecot", "Dovecot POP3"),
    ],
    "imap": [
        (r"\* OK.*IMAP", "IMAP"),
        (r"Dovecot", "Dovecot IMAP"),
    ],
    "rdp": [
        (r"\x03\x00\x00", "RDP"),
    ],
    "vnc": [
        (r"RFB\s+([\d.]+)", "VNC"),
    ],
    "dns": [
        (r"BIND\s+([\d.]+)", "BIND DNS"),
    ],
    "elastic": [
        (r"elasticsearch", "Elasticsearch"),
    ],
    "docker": [
        (r"Docker", "Docker API"),
    ],
}

# Known port-to-service mapping for identification without banners
PORT_SERVICE_MAP: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    88: "kerberos", 110: "pop3", 111: "rpc", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 179: "bgp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 500: "ike", 514: "syslog", 515: "printer",
    520: "rip", 523: "ibm-db2", 530: "courier", 548: "afp",
    554: "rtsp", 563: "nntps", 587: "submission", 631: "ipp",
    636: "ldaps", 873: "rsync", 902: "vmware", 993: "imaps",
    995: "pop3s", 1080: "socks", 1099: "rmi", 1194: "openvpn",
    1433: "mssql", 1434: "mssql-udp", 1521: "oracle", 1723: "pptp",
    1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 2222: "ssh-alt",
    3000: "grafana", 3306: "mysql", 3389: "rdp", 3690: "svn",
    4443: "https-alt", 4444: "metasploit", 5000: "docker-registry",
    5432: "postgresql", 5555: "adb", 5672: "amqp", 5900: "vnc",
    5984: "couchdb", 6379: "redis", 6443: "kubernetes",
    6667: "irc", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9090: "prometheus",
    9200: "elasticsearch", 9418: "git", 11211: "memcached",
    27017: "mongodb", 50000: "sap",
}


class PortScanner(BaseScanner):
    """Async TCP port scanner with banner grabbing and service fingerprinting.

    Scans specified ports (default: top 1000) using async TCP connections.
    Performs banner grabbing on open ports and fingerprints services based
    on response patterns.
    """

    @property
    def module_name(self) -> str:
        return "port_scanner"

    async def scan_port(
        self, host: str, port: int, semaphore: asyncio.Semaphore
    ) -> Optional[dict[str, Any]]:
        """Scan a single port for connectivity and banner.

        Args:
            host: Target hostname or IP.
            port: Port number to scan.
            semaphore: Concurrency limiting semaphore.

        Returns:
            Port result dict if open, None if closed/filtered.
        """
        async with semaphore:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(
                    conn, timeout=self.timeout
                )
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return None

            banner = ""
            service = PORT_SERVICE_MAP.get(port, "unknown")
            version = ""

            try:
                # Try to read a banner (some services send data immediately)
                banner_data = await asyncio.wait_for(
                    reader.read(1024), timeout=3.0
                )
                banner = banner_data.decode("utf-8", errors="replace").strip()
            except (asyncio.TimeoutError, UnicodeDecodeError, OSError):
                # No immediate banner; try sending probes
                try:
                    probes = self._get_probes(port)
                    for probe in probes:
                        writer.write(probe)
                        await writer.drain()
                        try:
                            response = await asyncio.wait_for(
                                reader.read(1024), timeout=2.0
                            )
                            banner = response.decode("utf-8", errors="replace").strip()
                            if banner:
                                break
                        except (asyncio.TimeoutError, OSError):
                            continue
                except OSError:
                    pass

            # Fingerprint the service from banner
            if banner:
                detected_service, detected_version = self._fingerprint_service(banner)
                if detected_service:
                    service = detected_service
                    version = detected_version

            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, AttributeError):
                pass

            return {
                "port": port,
                "state": "open",
                "service": service,
                "version": version,
                "banner": banner[:500],  # Limit banner length
            }

    def _get_probes(self, port: int) -> list[bytes]:
        """Get protocol-specific probes for banner grabbing.

        Args:
            port: Port number to determine appropriate probes.

        Returns:
            List of probe bytes to send.
        """
        probes = []
        if port in (80, 8080, 8000, 8888, 8443, 443, 8008, 8081):
            probes.append(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
        if port in (6379,):
            probes.append(b"PING\r\n")
        if port in (11211,):
            probes.append(b"stats\r\n")
        if port in (27017,):
            # MongoDB wire protocol isMaster
            probes.append(b"\x3a\x00\x00\x00")
        # Generic probe
        probes.append(b"\r\n\r\n")
        probes.append(b"HELP\r\n")
        return probes

    def _fingerprint_service(self, banner: str) -> tuple[str, str]:
        """Identify service and version from banner text.

        Args:
            banner: Raw banner string from the service.

        Returns:
            Tuple of (service_name, version_string).
        """
        for service_name, patterns in SERVICE_PATTERNS.items():
            for pattern, label in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else ""
                    return label, version
        return "", ""

    async def resolve_target(self) -> str:
        """Resolve target hostname to IP address.

        Returns:
            IP address string.
        """
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(
                self.target, None, family=socket.AF_INET
            )
            if result:
                return result[0][4][0]
        except (socket.gaierror, OSError):
            pass
        return self.target

    async def run(self) -> list[dict[str, Any]]:
        """Execute the port scan.

        Returns:
            List of result dictionaries for open ports found.
        """
        results: list[dict[str, Any]] = []
        host = await self.resolve_target()

        # Determine which ports to scan
        ports = self.config.get("ports", TOP_PORTS)
        if isinstance(ports, str):
            if ports == "top100":
                ports = TOP_PORTS[:100]
            elif ports == "top1000":
                ports = TOP_PORTS
            elif "-" in ports:
                start, end = ports.split("-")
                ports = list(range(int(start), int(end) + 1))

        await self.emit_event("port_scan_started", {
            "host": host,
            "port_count": len(ports),
        })

        semaphore = self.get_semaphore()

        # Scan all ports concurrently with semaphore
        tasks = [self.scan_port(host, port, semaphore) for port in ports]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports: list[dict[str, Any]] = []
        for result in scan_results:
            if isinstance(result, dict) and result is not None:
                open_ports.append(result)

        # Build result entries for each open port
        for port_info in open_ports:
            severity = "info"
            # Flag potentially dangerous services
            dangerous_services = ["telnet", "ftp", "rdp", "vnc", "redis", "mongodb", "memcached"]
            if port_info["service"] in dangerous_services:
                severity = "medium"
            if port_info["port"] in (23, 69, 512, 513, 514):
                severity = "high"

            result = self.build_result(
                title=f"Open port {port_info['port']}/{port_info['service']}",
                description=(
                    f"Port {port_info['port']} is open running {port_info['service']}"
                    f"{' ' + port_info['version'] if port_info['version'] else ''}"
                ),
                severity=severity,
                evidence=port_info["banner"] if port_info["banner"] else "Port responded to TCP connection",
                host=host,
                port=port_info["port"],
                protocol="tcp",
                data={
                    "service": port_info["service"],
                    "version": port_info["version"],
                    "banner": port_info["banner"],
                    "state": port_info["state"],
                },
                confidence=0.95 if port_info["banner"] else 0.8,
            )
            results.append(result)

        await self.emit_event("port_scan_completed", {
            "host": host,
            "open_ports": len(open_ports),
            "total_scanned": len(ports),
        })

        return results
