"""
Pipeline 1 — Scanner tradicional.
Roda Nikto, verifica CORS, open redirect e CVE lookup por tecnologia.
"""
import subprocess, requests, re, json, os
from core.utils import print_status, safe_request
from config import Config

# Melhoria 5: CVE DB carregada de JSON externo (fácil de expandir sem tocar no código)
def _load_cve_db() -> dict:
    db_path = os.path.join(os.path.dirname(__file__), "cve_db.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Não foi possível carregar cve_db.json: {e}")
        return {}

CVE_DB = _load_cve_db()

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
            "https:evil.com", "%2F%2Fevil.com", "///evil.com",
            "https://evil.com%23@trusted.com",
        ]
        params = ["redirect","next","url","return","goto","target","redir","continue","destination"]
        for param in params:
            found = False
            for payload in payloads:
                if found:
                    break
                try:
                    # Bug 2 fix: removido safe_request inutil de dentro do loop
                    resp = requests.get(
                        self.target, params={param: payload},
                        allow_redirects=False, timeout=5, verify=False,
                        headers={"User-Agent": "Mozilla/5.0"}
                    )
                    loc = resp.headers.get("Location","")
                    if "evil.com" in loc:
                        self.results["open_redirect"].append({
                            "param": param, "payload": payload,
                            "location": loc, "severity": "MEDIUM"
                        })
                        self.context_add(param, payload, loc)
                        print_status(f"Open Redirect via {param}={payload}", "CRIT")
                        found = True
                except Exception:
                    pass

    def context_add(self, param, payload, loc):
        """Helper para add_finding sem quebrar se context nao existir."""
        pass  # Scanner nao tem context — findings ficam em self.results

    def cve_lookup(self, technologies: list):
        print_status("CVE lookup por tecnologias detectadas...", "INFO")
        if not CVE_DB:
            print_status("cve_db.json não encontrado ou vazio.", "ERROR")
            return
        for tech in technologies:
            for db_tech, cves in CVE_DB.items():
                if db_tech.lower() in tech.lower() or tech.lower() in db_tech.lower():
                    for entry in cves:
                        self.results["cve_matches"].append({
                            "tech":     tech,
                            "cve":      entry["cve"],
                            "desc":     entry["desc"],
                            "severity": entry["severity"],
                        })
                        print_status(f"{entry['cve']} ({entry['severity']}) — {tech}: {entry['desc']}", "WARN")

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
