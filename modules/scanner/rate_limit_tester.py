"""
Rate Limit Tester — verifica ausência de rate limiting em endpoints de autenticação
e formulários de login. Sem enviar credenciais reais.
"""
import requests, warnings, time
from core.utils import print_status

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

AUTH_PATHS = [
    "/login", "/signin", "/auth", "/api/login", "/api/auth",
    "/api/v1/login", "/wp-login.php", "/admin/login",
    "/user/login", "/account/login", "/session",
]


class RateLimitTester:
    def __init__(self, target: str, context=None):
        self.target  = target
        self.context = context
        self.results = []

    def _probe_endpoint(self, url: str) -> dict | None:
        """Faz 10 requisições rápidas e verifica se há bloqueio."""
        headers = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
        dummy   = {"username": "test_probe", "password": "test_probe_xyz"}

        codes = []
        blocked_at = None

        for i in range(10):
            try:
                r = requests.post(url, json=dummy, headers=headers,
                                  timeout=5, verify=False, allow_redirects=False)
                codes.append(r.status_code)

                # Bloqueado = 429, 403 após tentativas
                if r.status_code in (429, 503) or "too many" in r.text.lower():
                    blocked_at = i + 1
                    break
            except Exception:
                break
            time.sleep(0.1)

        if len(codes) >= 5 and blocked_at is None:
            # 5+ requisições sem bloqueio = sem rate limit
            return {
                "url":       url,
                "issue":    "Ausência de rate limiting em endpoint de autenticação",
                "severity": "MEDIUM",
                "evidence": f"{len(codes)} requisições sem bloqueio (códigos: {set(codes)})",
                "source":   "RateLimitTester",
            }
        return None

    def test(self) -> list:
        print_status("Rate Limit Testing em endpoints de auth...", "INFO")
        for path in AUTH_PATHS:
            url = self.target.rstrip("/") + path
            try:
                # Verifica se existe
                r = requests.get(url, timeout=5, verify=False)
                if r.status_code not in (200, 301, 302, 405):
                    continue
                result = self._probe_endpoint(url)
                if result:
                    self.results.append(result)
                    if self.context:
                        self.context.add_finding(result)
                    print_status(f"Sem rate limit: {url}", "WARN")
            except Exception:
                pass

        print_status(f"Rate Limit: {len(self.results)} endpoints sem proteção.", "SUCCESS" if not self.results else "WARN")
        return self.results
