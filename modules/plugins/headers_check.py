from modules.plugins.base_plugin import BasePlugin

REQUIRED = [
    "Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options",
    "Content-Security-Policy","Referrer-Policy","Permissions-Policy"
]

class HeadersCheck(BasePlugin):
    name     = "headers_check"
    severity = "MEDIUM"

    def run(self, url, response):
        missing = [h for h in REQUIRED if h not in response.headers]
        if missing:
            return {
                "url": url,
                "issue": f"Security headers ausentes: {', '.join(missing)}",
                "severity": self.severity,
                "source": "Plugin:HeadersCheck"
            }
