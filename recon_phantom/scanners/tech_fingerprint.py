"""Technology fingerprinting scanner.

Detects web technologies from HTTP headers, cookies, HTML content,
JavaScript references, and response patterns. Identifies frameworks,
CMS platforms, programming languages, and server software.
"""

import re
from typing import Any, Optional

import httpx

from recon_phantom.scanners.base import BaseScanner


# Header-based technology signatures
HEADER_SIGNATURES: dict[str, list[tuple[str, str, str]]] = {
    # (header_name, pattern, technology_name)
    "server": [
        ("Server", r"Apache/([\d.]+)", "Apache"),
        ("Server", r"nginx/([\d.]+)", "nginx"),
        ("Server", r"Microsoft-IIS/([\d.]+)", "IIS"),
        ("Server", r"LiteSpeed", "LiteSpeed"),
        ("Server", r"openresty/([\d.]+)", "OpenResty"),
        ("Server", r"Caddy", "Caddy"),
        ("Server", r"Kestrel", "Kestrel"),
        ("Server", r"gunicorn", "Gunicorn"),
        ("Server", r"Werkzeug/([\d.]+)", "Werkzeug"),
        ("Server", r"Cowboy", "Cowboy (Erlang)"),
        ("Server", r"Jetty", "Jetty"),
        ("Server", r"Tomcat", "Apache Tomcat"),
        ("Server", r"Tengine", "Tengine"),
        ("Server", r"cloudflare", "Cloudflare"),
    ],
    "x-powered-by": [
        ("X-Powered-By", r"PHP/([\d.]+)", "PHP"),
        ("X-Powered-By", r"ASP\.NET", "ASP.NET"),
        ("X-Powered-By", r"Express", "Express.js"),
        ("X-Powered-By", r"Next\.js", "Next.js"),
        ("X-Powered-By", r"Phusion Passenger", "Passenger"),
        ("X-Powered-By", r"Django", "Django"),
        ("X-Powered-By", r"Flask", "Flask"),
        ("X-Powered-By", r"Ruby", "Ruby"),
        ("X-Powered-By", r"Servlet", "Java Servlet"),
        ("X-Powered-By", r"PleskLin", "Plesk"),
    ],
    "framework": [
        ("X-AspNet-Version", r"([\d.]+)", "ASP.NET"),
        ("X-AspNetMvc-Version", r"([\d.]+)", "ASP.NET MVC"),
        ("X-Drupal-Cache", r".*", "Drupal"),
        ("X-Generator", r"Drupal", "Drupal"),
        ("X-Generator", r"WordPress", "WordPress"),
        ("X-Shopify-Stage", r".*", "Shopify"),
        ("X-Wix-Request-Id", r".*", "Wix"),
        ("X-Turbo-Charged-By", r"LiteSpeed", "LiteSpeed Cache"),
        ("X-Varnish", r".*", "Varnish"),
        ("X-Cache", r".*HIT.*", "CDN Cache"),
        ("Via", r".*varnish.*", "Varnish"),
        ("X-Amz-Cf-Id", r".*", "AWS CloudFront"),
        ("X-Fastly-Request-ID", r".*", "Fastly"),
    ],
}

# Cookie-based technology detection
COOKIE_SIGNATURES: dict[str, str] = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "connect.sid": "Express.js",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "CAKEPHP": "CakePHP",
    "symfony": "Symfony",
    "rack.session": "Ruby/Rack",
    "_rails_session": "Ruby on Rails",
    "django_session": "Django",
    "flask_session": "Flask",
    "wp-settings": "WordPress",
    "wordpress_logged_in": "WordPress",
    "drupal_uid": "Drupal",
    "Magento": "Magento",
    "PrestaShop": "PrestaShop",
    "CRAFT_CSRF_TOKEN": "Craft CMS",
    "october_session": "October CMS",
    "__cfduid": "Cloudflare",
    "_ga": "Google Analytics",
    "_gid": "Google Analytics",
    "fbp": "Facebook Pixel",
    "__stripe_mid": "Stripe",
    "ajs_user_id": "Segment",
    "hubspotutk": "HubSpot",
    "intercom-session": "Intercom",
}

# HTML meta tag patterns
META_SIGNATURES: list[tuple[str, str, str]] = [
    (r'<meta\s+name=["\']generator["\']\s+content=["\'](WordPress\s*[\d.]*)["\']', "WordPress", "cms"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\'](Drupal\s*[\d.]*)["\']', "Drupal", "cms"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\'](Joomla!?\s*[\d.]*)["\']', "Joomla", "cms"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\'](TYPO3\s*[\d.]*)["\']', "TYPO3", "cms"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\'](Ghost\s*[\d.]*)["\']', "Ghost", "cms"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\'](Hugo\s*[\d.]*)["\']', "Hugo", "ssg"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\'](Jekyll\s*[\d.]*)["\']', "Jekyll", "ssg"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\'](Gatsby\s*[\d.]*)["\']', "Gatsby", "ssg"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\'](Hexo\s*[\d.]*)["\']', "Hexo", "ssg"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\'](Pelican\s*[\d.]*)["\']', "Pelican", "ssg"),
    (r'<meta\s+content=["\']Shopify["\']', "Shopify", "ecommerce"),
    (r'<meta\s+name=["\']author["\']\s+content=["\']Squarespace["\']', "Squarespace", "cms"),
]

# JavaScript/script source patterns
SCRIPT_SIGNATURES: list[tuple[str, str, str]] = [
    (r"jquery[.-]?([\d.]+)?(?:\.min)?\.js", "jQuery", "library"),
    (r"react[.-]?([\d.]+)?(?:\.production)?(?:\.min)?\.js", "React", "framework"),
    (r"vue[.-]?([\d.]+)?(?:\.min)?\.js", "Vue.js", "framework"),
    (r"angular[.-]?([\d.]+)?(?:\.min)?\.js", "Angular", "framework"),
    (r"angular\.io", "Angular", "framework"),
    (r"next/static", "Next.js", "framework"),
    (r"_next/", "Next.js", "framework"),
    (r"nuxt", "Nuxt.js", "framework"),
    (r"gatsby", "Gatsby", "framework"),
    (r"svelte", "Svelte", "framework"),
    (r"backbone[.-]?([\d.]+)?(?:\.min)?\.js", "Backbone.js", "library"),
    (r"ember[.-]?([\d.]+)?(?:\.min)?\.js", "Ember.js", "framework"),
    (r"bootstrap[.-]?([\d.]+)?(?:\.min)?\.js", "Bootstrap", "ui"),
    (r"tailwind", "Tailwind CSS", "ui"),
    (r"material-ui|@mui", "Material-UI", "ui"),
    (r"webpack", "Webpack", "bundler"),
    (r"chunk\.[a-f0-9]+\.js", "Webpack", "bundler"),
    (r"main\.[a-f0-9]+\.js", "Bundled App", "bundler"),
    (r"wp-content/", "WordPress", "cms"),
    (r"wp-includes/", "WordPress", "cms"),
    (r"/sites/default/files/", "Drupal", "cms"),
    (r"cdn\.shopify\.com", "Shopify", "ecommerce"),
    (r"static\.squarespace\.com", "Squarespace", "cms"),
    (r"assets\.squarespace\.com", "Squarespace", "cms"),
    (r"googleapis\.com/ajax/libs", "Google CDN", "cdn"),
    (r"cdnjs\.cloudflare\.com", "Cloudflare CDN", "cdn"),
    (r"unpkg\.com", "unpkg CDN", "cdn"),
    (r"jsdelivr\.net", "jsDelivr CDN", "cdn"),
    (r"gtag/js|google-analytics|googletagmanager", "Google Analytics", "analytics"),
    (r"facebook\.net/en_US/fbevents", "Facebook Pixel", "analytics"),
    (r"hotjar\.com", "Hotjar", "analytics"),
    (r"segment\.com/analytics", "Segment", "analytics"),
    (r"mixpanel", "Mixpanel", "analytics"),
    (r"amplitude", "Amplitude", "analytics"),
    (r"sentry[.-]?([\d.]+)?(?:\.min)?\.js|sentry\.io", "Sentry", "monitoring"),
    (r"newrelic", "New Relic", "monitoring"),
    (r"datadog", "Datadog", "monitoring"),
    (r"recaptcha", "Google reCAPTCHA", "security"),
    (r"hcaptcha", "hCaptcha", "security"),
    (r"turnstile", "Cloudflare Turnstile", "security"),
    (r"stripe\.js|js\.stripe\.com", "Stripe", "payment"),
    (r"paypal", "PayPal", "payment"),
]

# HTML body patterns
BODY_SIGNATURES: list[tuple[str, str, str]] = [
    (r"Powered by <a[^>]*>WordPress</a>", "WordPress", "cms"),
    (r'id=["\']__next["\']', "Next.js", "framework"),
    (r'id=["\']__nuxt["\']', "Nuxt.js", "framework"),
    (r'id=["\']app["\'].*data-v-', "Vue.js", "framework"),
    (r"ng-version", "Angular", "framework"),
    (r"data-reactroot", "React", "framework"),
    (r"data-react-helmet", "React Helmet", "library"),
    (r"___gatsby", "Gatsby", "framework"),
    (r"data-turbo", "Hotwire/Turbo", "framework"),
    (r"data-controller.*stimulus", "Stimulus", "framework"),
    (r"<!-- This is Squarespace -->", "Squarespace", "cms"),
    (r"<!-- Powered by Blogger -->", "Blogger", "cms"),
    (r"var defined_Wix", "Wix", "cms"),
    (r"Shopify\.theme", "Shopify", "ecommerce"),
    (r"WooCommerce", "WooCommerce", "ecommerce"),
    (r"Magento", "Magento", "ecommerce"),
]


class TechFingerprintScanner(BaseScanner):
    """Technology stack detection scanner.

    Identifies web technologies by analyzing HTTP response headers, cookies,
    HTML content, script sources, and various response patterns.
    """

    @property
    def module_name(self) -> str:
        return "tech_fingerprint"

    async def fetch_page(self, url: str) -> Optional[httpx.Response]:
        """Fetch a web page for analysis.

        Args:
            url: URL to fetch.

        Returns:
            HTTP response or None on failure.
        """
        return await self.make_request(url)

    def analyze_headers(self, response: httpx.Response) -> list[dict[str, Any]]:
        """Analyze HTTP headers for technology signatures.

        Args:
            response: HTTP response to analyze.

        Returns:
            List of detected technology dicts.
        """
        detections: list[dict[str, Any]] = []
        headers = response.headers

        for category, signatures in HEADER_SIGNATURES.items():
            for header_name, pattern, tech_name in signatures:
                header_value = headers.get(header_name.lower(), "")
                if header_value:
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.lastindex else ""
                        detections.append({
                            "technology": tech_name,
                            "version": version,
                            "category": category,
                            "source": f"header:{header_name}",
                            "evidence": f"{header_name}: {header_value}",
                            "confidence": 0.95,
                        })

        return detections

    def analyze_cookies(self, response: httpx.Response) -> list[dict[str, Any]]:
        """Analyze cookies for technology signatures.

        Args:
            response: HTTP response to analyze.

        Returns:
            List of detected technology dicts.
        """
        detections: list[dict[str, Any]] = []
        cookies = response.cookies

        for cookie_name, tech_name in COOKIE_SIGNATURES.items():
            for cookie in cookies.jar:
                if cookie_name.lower() in cookie.name.lower():
                    detections.append({
                        "technology": tech_name,
                        "version": "",
                        "category": "cookie",
                        "source": f"cookie:{cookie.name}",
                        "evidence": f"Cookie: {cookie.name}",
                        "confidence": 0.85,
                    })
                    break

        return detections

    def analyze_html_meta(self, html: str) -> list[dict[str, Any]]:
        """Analyze HTML meta tags for technology signatures.

        Args:
            html: HTML content string.

        Returns:
            List of detected technology dicts.
        """
        detections: list[dict[str, Any]] = []

        for pattern, tech_name, category in META_SIGNATURES:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                version = ""
                full_match = match.group(0)
                # Try to extract version
                version_match = re.search(r"([\d.]+)", match.group(1) if match.lastindex else "")
                if version_match:
                    version = version_match.group(1)

                detections.append({
                    "technology": tech_name,
                    "version": version,
                    "category": category,
                    "source": "meta_tag",
                    "evidence": full_match[:200],
                    "confidence": 0.9,
                })

        return detections

    def analyze_scripts(self, html: str) -> list[dict[str, Any]]:
        """Analyze script sources and inline scripts for technology patterns.

        Args:
            html: HTML content string.

        Returns:
            List of detected technology dicts.
        """
        detections: list[dict[str, Any]] = []
        seen_tech: set[str] = set()

        # Extract script src attributes
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        # Also check link tags for CSS
        link_hrefs = re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE)

        all_refs = script_srcs + link_hrefs + [html]

        for ref in all_refs:
            for pattern, tech_name, category in SCRIPT_SIGNATURES:
                if tech_name in seen_tech:
                    continue
                match = re.search(pattern, ref, re.IGNORECASE)
                if match:
                    version = ""
                    if match.lastindex:
                        version = match.group(1) or ""
                    seen_tech.add(tech_name)
                    detections.append({
                        "technology": tech_name,
                        "version": version,
                        "category": category,
                        "source": "script_src",
                        "evidence": ref[:200] if ref != html else match.group(0)[:200],
                        "confidence": 0.85,
                    })

        return detections

    def analyze_body(self, html: str) -> list[dict[str, Any]]:
        """Analyze HTML body patterns for technology signatures.

        Args:
            html: HTML content string.

        Returns:
            List of detected technology dicts.
        """
        detections: list[dict[str, Any]] = []
        seen_tech: set[str] = set()

        for pattern, tech_name, category in BODY_SIGNATURES:
            if tech_name in seen_tech:
                continue
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                seen_tech.add(tech_name)
                detections.append({
                    "technology": tech_name,
                    "version": "",
                    "category": category,
                    "source": "html_body",
                    "evidence": match.group(0)[:200],
                    "confidence": 0.8,
                })

        return detections

    def deduplicate_detections(
        self, detections: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Remove duplicate technology detections, keeping highest confidence.

        Args:
            detections: List of all detected technologies.

        Returns:
            Deduplicated list with highest confidence for each technology.
        """
        best: dict[str, dict[str, Any]] = {}
        for det in detections:
            key = det["technology"]
            if key not in best or det["confidence"] > best[key]["confidence"]:
                best[key] = det
            elif key in best and det["version"] and not best[key]["version"]:
                best[key]["version"] = det["version"]
        return list(best.values())

    async def run(self) -> list[dict[str, Any]]:
        """Execute technology fingerprinting scan.

        Returns:
            List of result dictionaries for detected technologies.
        """
        results: list[dict[str, Any]] = []
        all_detections: list[dict[str, Any]] = []

        # Try both HTTP and HTTPS
        urls = []
        base = self._get_base_domain_clean()
        if self.target.startswith(("http://", "https://")):
            urls = [self.target]
        else:
            urls = [f"https://{base}", f"http://{base}"]

        for url in urls:
            response = await self.fetch_page(url)
            if response is None:
                continue

            # Analyze headers
            header_detections = self.analyze_headers(response)
            all_detections.extend(header_detections)

            # Analyze cookies
            cookie_detections = self.analyze_cookies(response)
            all_detections.extend(cookie_detections)

            # Analyze HTML content
            html = response.text
            if html:
                meta_detections = self.analyze_html_meta(html)
                all_detections.extend(meta_detections)

                script_detections = self.analyze_scripts(html)
                all_detections.extend(script_detections)

                body_detections = self.analyze_body(html)
                all_detections.extend(body_detections)

            # Only need one successful response
            if all_detections:
                break

        # Deduplicate
        unique_detections = self.deduplicate_detections(all_detections)

        # Build results
        for detection in unique_detections:
            tech = detection["technology"]
            version = detection["version"]
            title = f"Technology detected: {tech}"
            if version:
                title += f" {version}"

            result = self.build_result(
                title=title,
                description=(
                    f"Detected {tech}"
                    f"{' version ' + version if version else ''}"
                    f" via {detection['source']}"
                ),
                severity="info",
                evidence=detection["evidence"],
                host=self.target,
                protocol="http",
                data={
                    "technology": tech,
                    "version": version,
                    "category": detection["category"],
                    "source": detection["source"],
                },
                confidence=detection["confidence"],
            )
            results.append(result)

        await self.emit_event("tech_fingerprint_completed", {
            "technologies_found": len(results),
        })

        return results

    def _get_base_domain_clean(self) -> str:
        """Get clean base domain without protocol or path."""
        target = self.target.lower().strip()
        if "://" in target:
            target = target.split("://", 1)[1]
        target = target.split("/")[0]
        target = target.split(":")[0]
        return target
