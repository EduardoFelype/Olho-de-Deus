"""
JWT Analyzer — detecta e analisa tokens JWT em páginas, headers e cookies.
Verifica algoritmo fraco, alg:none, expiração, claims sensíveis e segredo fraco.
"""
import re, base64, json, time
from core.utils import print_status

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*")

WEAK_ALGOS  = ["none", "hs256"]  # HS256 não é necessariamente fraco mas merece atenção
DANGER_CLAIMS = ["admin", "role", "isAdmin", "is_admin", "superuser", "privilege", "permission", "scope"]

COMMON_SECRETS = [
    "secret","password","123456","qwerty","admin","test","key","jwt",
    "mysecret","change_me","supersecret","jwtkey","token","secret123",
    "your-256-bit-secret","your-secret-key","jwt_secret","app_secret",
]


def _b64_decode(s: str) -> dict:
    s += "=" * (-len(s) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(s))
    except Exception:
        return {}


class JWTAnalyzer:
    def __init__(self):
        self.results = []

    def _analyze_token(self, token: str, source: str) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            return {}

        header  = _b64_decode(parts[0])
        payload = _b64_decode(parts[1])
        sig     = parts[2]

        issues = []

        # Algoritmo none
        alg = header.get("alg", "").lower()
        if alg == "none":
            issues.append({"issue": "JWT com alg:none — assinatura ignorada", "severity": "CRITICAL"})

        # Algoritmo fraco
        if alg in ("hs256",) and not sig:
            issues.append({"issue": "JWT sem assinatura (alg HS256 sem sig)", "severity": "CRITICAL"})

        # Expirado
        exp = payload.get("exp")
        if exp and exp < time.time():
            issues.append({"issue": f"JWT expirado (exp: {exp})", "severity": "LOW"})

        # Sem expiração
        if not exp:
            issues.append({"issue": "JWT sem campo 'exp' — token não expira", "severity": "MEDIUM"})

        # Claims sensíveis
        for claim in DANGER_CLAIMS:
            if claim in payload:
                issues.append({
                    "issue":    f"Claim sensível '{claim}' = {payload[claim]}",
                    "severity": "HIGH"
                })

        # Segredo fraco (brute force básico com HMAC)
        try:
            import hmac, hashlib
            msg = f"{parts[0]}.{parts[1]}".encode()
            real_sig = base64.urlsafe_b64decode(sig + "==")
            for secret in COMMON_SECRETS:
                candidate = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
                if candidate == real_sig:
                    issues.append({
                        "issue":    f"JWT segredo fraco descoberto: '{secret}'",
                        "severity": "CRITICAL"
                    })
                    break
        except Exception:
            pass

        return {
            "token":   token[:60] + "…",
            "source":  source,
            "header":  header,
            "payload": {k: v for k, v in payload.items() if k not in ("iat","nbf")},
            "issues":  issues,
        }

    def scan_pages(self, pages: list) -> list:
        print_status("JWT Analyzer em páginas e JS...", "INFO")
        seen = set()
        for page in pages:
            # Busca no HTML/JS
            for token in JWT_PATTERN.findall(page["html"]):
                if token not in seen:
                    seen.add(token)
                    result = self._analyze_token(token, page["url"])
                    if result:
                        self.results.append(result)

            # Busca em cookies da resposta (headers)
            cookie_header = page["headers"].get("Set-Cookie", "")
            for token in JWT_PATTERN.findall(cookie_header):
                if token not in seen:
                    seen.add(token)
                    result = self._analyze_token(token, f"{page['url']} [cookie]")
                    if result:
                        self.results.append(result)

        crit = sum(1 for r in self.results for i in r.get("issues",[]) if i.get("severity")=="CRITICAL")
        print_status(f"JWT: {len(self.results)} tokens, {crit} issues críticos.", "WARN" if crit else "SUCCESS")
        return self.results
