import whois, ssl, socket, dns.resolver
from googlesearch import search
from urllib.parse import urlparse
from core.utils import print_status

SECURITY_HEADERS = [
    "Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options",
    "Content-Security-Policy","Referrer-Policy","Permissions-Policy"
]

class PassiveRecon:
    def __init__(self, target):
        self.target  = target
        self.domain  = urlparse(target).netloc or target
        self.results = {"whois":{},"dns":[],"dorks":[],"ssl":{}}

    def run_whois(self):
        try:
            w = whois.whois(self.domain)
            self.results["whois"] = {
                "registrar": w.registrar,
                "creation":  str(w.creation_date),
                "expiry":    str(w.expiration_date),
                "emails":    w.emails
            }
            print_status("WHOIS OK", "SUCCESS")
        except Exception as e:
            print_status(f"WHOIS: {e}", "WARN")

    def run_dns(self):
        for rtype in ["A","MX","NS","TXT","CNAME","AAAA"]:
            try:
                for a in dns.resolver.resolve(self.domain, rtype):
                    self.results["dns"].append(f"{rtype}: {a}")
            except Exception:
                pass
        print_status(f"{len(self.results['dns'])} registros DNS.", "SUCCESS")

    def run_dorks(self):
        dorks = [
            f"site:{self.domain} ext:sql|env|log|bak|conf",
            f"site:{self.domain} inurl:admin|login|dashboard",
            f"site:{self.domain} intext:password|token|secret",
        ]
        for d in dorks:
            try:
                self.results["dorks"].extend(list(search(d, num_results=5)))
            except Exception:
                pass
        print_status(f"{len(self.results['dorks'])} links dorks encontrados.", "WARN")

    def check_ssl(self):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as s:
                    cert = s.getpeercert()
                    self.results["ssl"] = {
                        "expire":  cert.get("notAfter"),
                        "subject": dict(x[0] for x in cert.get("subject",[])),
                        "issuer":  dict(x[0] for x in cert.get("issuer",[])),
                    }
            print_status("SSL OK", "SUCCESS")
        except Exception as e:
            print_status(f"SSL: {e}", "WARN")

    def execute_all(self):
        print_status("Recon Passivo...", "INFO")
        self.run_whois()
        self.run_dns()
        self.run_dorks()
        self.check_ssl()
        return self.results


def run_recon(target, context):
    """Entrypoint Pipeline 1."""
    print_status("[PIPELINE 1] Recon Passivo", "CRIT")
    context.add_url(target)
    r = PassiveRecon(target)
    return r.execute_all()
