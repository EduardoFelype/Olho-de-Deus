"""
Subdomain Enumeration — DNS brute + Certificate Transparency (crt.sh).
Não usa ferramentas externas, roda 100% em Python.
"""
import requests
import dns.resolver
import concurrent.futures
from core.utils import print_status

# Wordlist embutida — top subdomains
SUBDOMAIN_WORDLIST = [
    "www","mail","remote","blog","webmail","server","ns1","ns2","smtp","secure",
    "vpn","m","shop","ftp","mail2","test","portal","ns","ww1","host","support",
    "dev","web","bbs","ww42","mx","email","cloud","1","mail1","2","forum","owa",
    "www2","gw","admin","store","mx1","cdn","api","exchange","app","gov","2tty",
    "vps","govyv","media","email2","ns3","info","mail3","imap","tv","smtp2",
    "new","mysql","old","www1","newsletter","git","services","panel","staging",
    "static","beta","login","demo","dashboard","back","monitor","internal",
    "corp","vpn2","docs","intranet","stage","prod","production","preview",
    "jenkins","ci","jira","confluence","gitlab","grafana","kibana","elastic",
]

TAKEOVER_SIGNATURES = {
    "GitHub Pages":       "There isn't a GitHub Pages site here",
    "Heroku":             "No such app",
    "Netlify":            "Not Found - Request ID",
    "Vercel":             "The deployment you are looking for",
    "AWS S3":             "NoSuchBucket",
    "Azure":              "404 Web Site not found",
    "Shopify":            "Sorry, this shop is currently unavailable",
    "Tumblr":             "There's nothing here",
    "Ghost":              "The thing you were looking for is no longer here",
    "Fastly":             "Fastly error: unknown domain",
}


class SubdomainEnumerator:
    def __init__(self, domain: str, context=None):
        self.domain  = domain
        self.context = context
        self.found   = []
        self.takeover_risks = []

    def _resolve(self, sub: str) -> dict | None:
        fqdn = f"{sub}.{self.domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            return {"subdomain": fqdn, "ips": ips}
        except Exception:
            return None

    def brute_dns(self):
        print_status(f"DNS brute ({len(SUBDOMAIN_WORDLIST)} subdomains)...", "INFO")
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            results = list(ex.map(self._resolve, SUBDOMAIN_WORDLIST))
        for r in results:
            if r:
                self.found.append(r)
                if self.context:
                    self.context.add_url(f"http://{r['subdomain']}")
        print_status(f"DNS brute: {len(self.found)} subdomains ativos.", "SUCCESS")

    def crt_sh(self):
        print_status("Certificate Transparency (crt.sh)...", "INFO")
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=15
            )
            if r.status_code != 200:
                return
            seen = set()
            for entry in r.json():
                name = entry.get("name_value","").lower().strip()
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(self.domain) and sub not in seen:
                        seen.add(sub)
                        # Verifica se resolve
                        try:
                            dns.resolver.resolve(sub, "A")
                            self.found.append({"subdomain": sub, "source": "crt.sh"})
                            if self.context:
                                self.context.add_url(f"http://{sub}")
                        except Exception:
                            pass
            print_status(f"crt.sh: {len(seen)} nomes encontrados.", "SUCCESS")
        except Exception as e:
            print_status(f"crt.sh: {e}", "WARN")

    def check_takeover(self):
        print_status("Verificando subdomain takeover...", "INFO")
        for entry in self.found:
            sub = entry["subdomain"]
            try:
                r = requests.get(f"http://{sub}", timeout=6, allow_redirects=True)
                for service, signature in TAKEOVER_SIGNATURES.items():
                    if signature.lower() in r.text.lower():
                        risk = {
                            "subdomain": sub,
                            "service":   service,
                            "severity":  "HIGH",
                            "issue":     f"Possível Subdomain Takeover via {service}",
                        }
                        self.takeover_risks.append(risk)
                        if self.context:
                            self.context.add_finding({**risk, "url": f"http://{sub}", "source": "SubdomainTakeover"})
                        print_status(f"TAKEOVER RISCO: {sub} → {service}", "CRIT")
            except Exception:
                pass

    def run(self):
        self.brute_dns()
        self.crt_sh()
        self.check_takeover()
        return {
            "subdomains":      self.found,
            "takeover_risks":  self.takeover_risks,
        }
