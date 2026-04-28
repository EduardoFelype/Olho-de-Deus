from modules.plugins.base_plugin import BasePlugin

class CookieCheck(BasePlugin):
    name     = "cookie_check"
    severity = "MEDIUM"

    def run(self, url, response):
        issues = []
        for cookie in response.cookies:
            if not cookie.secure:
                issues.append(f"{cookie.name}: sem Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append(f"{cookie.name}: sem HttpOnly flag")
        if issues:
            return {
                "url": url,
                "issue": "Cookie inseguro: " + "; ".join(issues),
                "severity": self.severity,
                "source": "Plugin:CookieCheck"
            }
