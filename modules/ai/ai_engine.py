"""
Pipeline 3 — AI Engine.
Análise global, priorização inteligente, foco dinâmico e geração de insights.
"""
import re
from core.utils import print_status, safe_request
from modules.ai.learning_engine import LearningEngine
from modules.ai.risk_engine import RiskEngine
from modules.ai.evidence_engine import enrich_finding

# Padrões para análise de conteúdo
SENSITIVE_KEYWORDS = {
    "CRITICAL": ["-----BEGIN PRIVATE KEY", "-----BEGIN RSA PRIVATE KEY",
                 "AKIA", "password=", "secret=", "private_key"],
    "HIGH":     ["token", "api_key", "apikey", "authorization", "bearer",
                 "admin", "root", "sudo", "database_url"],
    "MEDIUM":   ["password", "passwd", "credential", "login", "auth", "session"],
    "LOW":      ["debug", "test", "todo", "fixme"],
}

SECRET_PATTERNS = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Live Key":   r"sk_live_[0-9a-zA-Z]{24,}",
    "GitHub Token":      r"ghp_[A-Za-z0-9]{36}",
    "Slack Token":       r"xox[baprs]-[0-9A-Za-z\-]+",
    "JWT Token":         r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "Generic API Key":   r"(?i)(api_key|apikey|api-key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
    "DB Connection":     r"(mongodb|postgres|postgresql|mysql|redis):\/\/[^\s'\"<>]+",
    "Private Key Block": r"-----BEGIN (RSA |OPENSSH |EC |PGP )?PRIVATE KEY-----",
    "Supabase Key":      r"eyJ[A-Za-z0-9\-_]{50,}\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
}

TECH_SIGNATURES = {
    "React":      ["__reactFiber","react.production.min.js","react-dom"],
    "Next.js":    ["__NEXT_DATA__","_next/static"],
    "Vue.js":     ["__vue__","vue.min.js","vue.runtime"],
    "Angular":    ["ng-version","angular.min.js"],
    "jQuery":     ["jquery.min.js","jquery-","$.fn.jquery"],
    "Bootstrap":  ["bootstrap.min.css","bootstrap.bundle"],
    "WordPress":  ["wp-content/","wp-includes/","wp-login.php"],
    "Laravel":    ["laravel_session","X-Powered-By: Laravel"],
    "Django":     ["csrfmiddlewaretoken"],
    "Firebase":   ["firebase","firebaseapp.com"],
    "Supabase":   ["supabase.co","supabase"],
    "PHP":        ["X-Powered-By: PHP",".php"],
    "Apache":     ["Server: Apache"],
    "Nginx":      ["Server: nginx"],
    "Cloudflare": ["cf-ray","cloudflare"],
}

XSS_PAYLOADS  = [
    "<script>alert(1)</script>", "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>", "\"><img src=x onerror=alert(1)>",
]
SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "' UNION SELECT null,null--",
    "' AND 1=CAST((SELECT version()) AS INT)--",
]
SQLI_ERRORS   = ["sql syntax","mysql_fetch","ora-","postgresql",
                 "sqlite","syntax error","unclosed quotation"]
SSRF_PAYLOADS = ["http://127.0.0.1","http://localhost",
                 "http://169.254.169.254/latest/meta-data/"]
COMMON_PARAMS = ["q","search","s","query","id","page","user",
                 "url","redirect","next","file","path","src","href"]


class AIEngine:
    def __init__(self, target, context):
        self.target   = target
        self.context  = context
        self.learning = LearningEngine()
        self.risk     = RiskEngine()
        self.results  = {
            "secrets":         [],
            "smart_analysis":  [],
            "technologies":    [],
            "exploitation":    [],
            "insights":        [],
            "prioritized":     [],
            "top_issues":      [],
        }

    # ── 1. Detecção de tecnologias ────────────────────────────────────────────
    def detect_technologies(self, pages, headers):
        techs = set()
        headers_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        for page in pages:
            html = page["html"].lower()
            for tech, sigs in TECH_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in html or sig.lower() in headers_str:
                        techs.add(tech)
        self.results["technologies"] = sorted(techs)
        print_status(f"Tecnologias: {self.results['technologies']}", "SUCCESS")

    # ── 2. Secret Scanner ─────────────────────────────────────────────────────
    def scan_secrets(self, pages):
        print_status("IA: Scanning secrets...", "INFO")
        seen = set()
        for page in pages:
            for label, pattern in SECRET_PATTERNS.items():
                for match in re.finditer(pattern, page["html"]):
                    raw = match.group(0)
                    val = raw
                    if match.lastindex:
                        for i in range(match.lastindex, 0, -1):
                            if match.group(i):
                                val = match.group(i)
                                break
                    key = f"{label}:{val[:30]}"
                    if key in seen:
                        continue
                    seen.add(key)
                    finding = {
                        "type": label, "value": val[:80],
                        "url": page["url"], "severity": "CRITICAL",
                        "source": "AI:SecretScanner"
                    }
                    self.results["secrets"].append(finding)
                    self.context.add_finding({**finding, "issue": f"Secret exposto: {label}"})
                    print_status(f"[CRÍTICO] {label} em {page['url']}", "CRIT")

    # ── 3. Smart Analyzer ─────────────────────────────────────────────────────
    def smart_analyze(self, pages):
        print_status("IA: Análise heurística...", "INFO")
        for page in pages:
            content = page["html"]
            content_lower = content.lower()
            for severity, keywords in SENSITIVE_KEYWORDS.items():
                for kw in keywords:
                    if kw.lower() in content_lower:
                        f = {
                            "url": page["url"],
                            "issue": f"Keyword sensível: '{kw}'",
                            "severity": severity,
                            "source": "AI:SmartAnalyzer"
                        }
                        self.results["smart_analysis"].append(f)
                        self.context.add_finding(f)
                        break

    # ── 4. Exploitation ───────────────────────────────────────────────────────
    def _req(self, url, param, payload, method="GET"):
        import requests as req
        try:
            if method == "GET":
                return req.get(url, params={param: payload}, timeout=8, verify=False)
            return req.post(url, data={param: payload}, timeout=8, verify=False)
        except Exception:
            return None

    def test_exploitation(self, pages):
        print_status("IA: Testes de exploração...", "INFO")

        # XSS + SQLi em params comuns
        for param in COMMON_PARAMS:
            for payload in XSS_PAYLOADS:
                for method in ("GET","POST"):
                    r = self._req(self.target, param, payload, method)
                    if r and payload in r.text:
                        f = {"type":"XSS Refletido","method":method,"param":param,
                             "payload":payload,"url":self.target,"severity":"HIGH","source":"AI:Exploiter"}
                        self.results["exploitation"].append(f)
                        self.context.add_finding({**f,"issue":"XSS Refletido"})
                        print_status(f"XSS em {param} [{method}]","CRIT")
                        break

            for payload in SQLI_PAYLOADS:
                for method in ("GET","POST"):
                    r = self._req(self.target, param, payload, method)
                    if not r:
                        continue
                    if any(e in r.text.lower() for e in SQLI_ERRORS):
                        f = {"type":"SQLi Error-Based","method":method,"param":param,
                             "payload":payload,"url":self.target,"severity":"CRITICAL","source":"AI:Exploiter"}
                        self.results["exploitation"].append(f)
                        self.context.add_finding({**f,"issue":"SQL Injection"})
                        print_status(f"SQLi em {param} [{method}]","CRIT")
                    elif r.status_code == 500:
                        f = {"type":"SQLi (HTTP 500)","method":method,"param":param,
                             "payload":payload,"url":self.target,"severity":"MEDIUM","source":"AI:Exploiter"}
                        self.results["exploitation"].append(f)
                        self.context.add_finding({**f,"issue":"Possível SQLi"})

        # SSRF
        for param in ["url","redirect","next","src","href","path"]:
            for payload in SSRF_PAYLOADS:
                import requests as req
                try:
                    r = req.get(self.target, params={param: payload},
                                allow_redirects=False, timeout=6, verify=False)
                    if r and r.status_code == 200 and len(r.text) > 100:
                        f = {"type":"Possível SSRF","param":param,"payload":payload,
                             "url":self.target,"severity":"HIGH","source":"AI:Exploiter"}
                        self.results["exploitation"].append(f)
                        self.context.add_finding({**f,"issue":"SSRF"})
                        print_status(f"SSRF via {param}","CRIT")
                        break
                except Exception:
                    pass

        # Forms descobertos pelo crawler
        for page in pages:
            for form in page.get("forms", []):
                action = form["action"]
                method = form["method"]
                inputs = form["inputs"]
                for field in inputs:
                    for payload in XSS_PAYLOADS[:2]:
                        import requests as req
                        try:
                            data = {f: payload for f in inputs}
                            r = req.request(method, action,
                                            data=data if method=="POST" else None,
                                            params=data if method=="GET" else None,
                                            timeout=8, verify=False)
                            if r and payload in r.text:
                                f_data = {"type":"XSS em Form","method":method,"param":field,
                                          "payload":payload,"url":action,"severity":"HIGH","source":"AI:FormTester"}
                                self.results["exploitation"].append(f_data)
                                self.context.add_finding({**f_data,"issue":"XSS em Form"})
                                print_status(f"XSS em form field '{field}'","CRIT")
                        except Exception:
                            pass

    # ── 5. Priorização inteligente + Insights ─────────────────────────────────
    def prioritize_and_learn(self):
        print_status("IA: Priorizando e gerando insights...", "INFO")
        all_f = self.context.all_findings()

        # Aprende com todos os issues
        for f in all_f:
            issue = f.get("issue") or f.get("type","")
            self.learning.learn(issue)

        # Prioriza
        prioritized = self.risk.prioritize(all_f)
        self.results["prioritized"] = prioritized[:60]

        top = self.learning.top_issues(8)
        self.results["top_issues"] = [{"issue": k, "count": v} for k, v in top]

        # Gera insights automáticos
        insights = []
        crit_count = sum(1 for f in prioritized if f.get("severity")=="CRITICAL")
        if crit_count > 0:
            insights.append(f"🔴 {crit_count} finding(s) CRÍTICO(s) — requerem atenção imediata antes de qualquer deploy.")

        if any("sqli" in (f.get("issue","") or f.get("type","")).lower() for f in prioritized):
            insights.append("💣 SQL Injection detectado — risco de exfiltração completa do banco de dados.")

        if any("secret" in (f.get("issue","") or f.get("type","")).lower() for f in prioritized):
            insights.append("🔑 Secrets expostos no frontend — rotacionar imediatamente todas as chaves afetadas.")

        if any("ssrf" in (f.get("issue","") or f.get("type","")).lower() for f in prioritized):
            insights.append("🌐 SSRF detectado — possível acesso a infraestrutura interna ou metadata de cloud.")

        if any("traversal" in (f.get("issue","") or "").lower() for f in prioritized):
            insights.append("📁 Path Traversal confirmado — leitura de arquivos arbitrários no servidor.")

        recurring = [k for k,v in top if v >= 2]
        if recurring:
            insights.append(f"🔁 Issues recorrentes entre scans: {', '.join(recurring[:3])} — padrão sistêmico.")

        self.results["insights"] = insights
        for ins in insights:
            print_status(ins, "WARN")

    # ── Run completo ──────────────────────────────────────────────────────────
    def run(self, pages, headers):
        self.detect_technologies(pages, headers)
        self.scan_secrets(pages)
        self.smart_analyze(pages)
        self.test_exploitation(pages)
        self.prioritize_and_learn()
        return self.results


def run_ai(target, context, pages, headers):
    """Entrypoint Pipeline 3."""
    print_status("[PIPELINE 3] AI Engine", "CRIT")
    engine = AIEngine(target, context)
    return engine.run(pages, headers)
