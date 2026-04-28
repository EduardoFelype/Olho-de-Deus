"""
Pipeline 1 — Scanner tradicional.
Roda Nikto, verifica CORS, open redirect e CVE lookup por tecnologia.
"""
import subprocess, requests, re
from core.utils import print_status, safe_request
from config import Config

# CVEs conhecidos por tech (amostra ilustrativa — expansível)
CVE_DB = {
    "WordPress":  [("CVE-2023-5561","Auth bypass via REST","HIGH"),
                   ("CVE-2022-21661","SQLi no WP_Query","CRITICAL")],
    "Laravel":    [("CVE-2021-3129","RCE via debug mode","CRITICAL")],
    "jQuery":     [("CVE-2019-11358","Prototype Pollution","MEDIUM")],
    "Apache":     [("CVE-2021-41773","Path Traversal/RCE","CRITICAL")],
    "Nginx":      [("CVE-2021-23017","1-byte heap overflow","HIGH")],
    "PHP":        [("CVE-2024-4577","Argument injection PHP-CGI","CRITICAL")],
}

class Scanner:
    def __init__(self, target):
        self.target  = target
        self.results = {"nikto":[], "cors":[], "open_redirect":[], "cve_matches":[]}

    def run_nikto(self):
        print_status("Nikto HTTP scan...", "INFO")
        try:
            cmd = [Config.NIKTO_PATH, "-h", self.target, "-ask=no", "-nointeractive"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            for line in proc.stdout.split("\n"):
                if line.startswith("+"):
                    self.results["nikto"].append(line.strip())
            print_status(f"Nikto: {len(self.results['nikto'])} alertas", "WARN")
        except FileNotFoundError:
            print_status("Nikto não instalado.", "ERROR")
        except Exception:
            pass

    def check_cors(self):
        print_status("Verificando CORS misconfiguration...", "INFO")
        origins = ["https://evil.com", "null", "https://attacker.io"]
        for origin in origins:
            r = safe_request(self.target, headers={"Origin": origin})
            if r:
                acao = r.headers.get("Access-Control-Allow-Origin","")
                acac = r.headers.get("Access-Control-Allow-Credentials","")
                if acao == origin or acao == "*":
                    self.results["cors"].append({
                        "origin": origin,
                        "ACAO": acao,
                        "ACAC": acac,
                        "severity": "HIGH" if acac.lower()=="true" else "MEDIUM"
                    })
                    print_status(f"CORS misconfiguration com origin={origin}", "CRIT")

    def check_open_redirect(self):
        print_status("Verificando Open Redirect...", "INFO")
        payloads = [
            "https://evil.com", "//evil.com", "/\\evil.com",
            "https:evil.com", "%2F%2Fevil.com"
        ]
        params = ["redirect","next","url","return","goto","target","redir"]
        for param in params:
            for payload in payloads:
                r = safe_request(self.target, headers={}, timeout=5)
                try:
                    resp = requests.get(
                        self.target, params={param: payload},
                        allow_redirects=False, timeout=5, verify=False
                    )
                    loc = resp.headers.get("Location","")
                    if "evil.com" in loc:
                        self.results["open_redirect"].append({
                            "param": param, "payload": payload, "severity": "MEDIUM"
                        })
                        print_status(f"Open Redirect via {param}", "CRIT")
                        break
                except Exception:
                    pass

    def cve_lookup(self, technologies: list):
        print_status("CVE lookup por tecnologias detectadas...", "INFO")
        for tech in technologies:
            for t, cves in CVE_DB.items():
                if t.lower() in tech.lower():
                    for cve_id, desc, sev in cves:
                        self.results["cve_matches"].append({
                            "tech": tech, "cve": cve_id,
                            "desc": desc, "severity": sev
                        })
                        print_status(f"{cve_id} ({sev}) — {tech}: {desc}", "WARN")

    def execute_all(self, technologies=None):
        self.run_nikto()
        self.check_cors()
        self.check_open_redirect()
        if technologies:
            self.cve_lookup(technologies)
        return self.results


def run_scanner(target, context):
    """Entrypoint Pipeline 1."""
    print_status("[PIPELINE 1] Scanner tradicional", "CRIT")
    s = Scanner(target)
    return s.execute_all()
