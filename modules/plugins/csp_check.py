from modules.plugins.base_plugin import BasePlugin

WEAK_DIRECTIVES = ["unsafe-inline","unsafe-eval","*"]

class CSPCheck(BasePlugin):
    name     = "csp_check"
    severity = "MEDIUM"

    def run(self, url, response):
        csp = response.headers.get("Content-Security-Policy","")
        if not csp:
            return {"url": url, "issue": "CSP ausente", "severity": "MEDIUM", "source": "Plugin:CSPCheck"}
        weak = [d for d in WEAK_DIRECTIVES if d in csp]
        if weak:
            return {
                "url": url,
                "issue": f"CSP fraca — diretivas perigosas: {weak}",
                "severity": "MEDIUM",
                "source": "Plugin:CSPCheck"
            }
