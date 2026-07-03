"""
SSL/TLS Analyzer — versões fracas, ciphers inseguros, cert expirado, HSTS ausente.
"""
import ssl, socket, datetime
from core.utils import print_status

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
WEAK_CIPHERS   = ["RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "anon"]


class SSLAnalyzer:
    def __init__(self, target: str, context=None):
        from urllib.parse import urlparse
        parsed       = urlparse(target)
        self.host    = parsed.netloc or target
        self.target  = target
        self.context = context
        self.results = {
            "cert":      {},
            "issues":    [],
            "protocol":  "",
            "cipher":    "",
        }

    def analyze(self):
        print_status("SSL/TLS Analysis...", "INFO")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((self.host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as s:
                    cert    = s.getpeercert()
                    proto   = s.version()
                    cipher  = s.cipher()

                    self.results["protocol"] = proto
                    self.results["cipher"]   = cipher[0] if cipher else ""

                    # Protocolo fraco
                    if any(w in proto for w in WEAK_PROTOCOLS):
                        issue = {
                            "issue":    f"Protocolo SSL/TLS fraco: {proto}",
                            "severity": "HIGH",
                            "source":   "SSLAnalyzer",
                            "url":      self.target,
                        }
                        self.results["issues"].append(issue)
                        if self.context:
                            self.context.add_finding(issue)
                        print_status(f"Protocolo fraco: {proto}", "CRIT")

                    # Cipher fraco
                    cipher_name = cipher[0] if cipher else ""
                    if any(w in cipher_name for w in WEAK_CIPHERS):
                        issue = {
                            "issue":    f"Cipher suite inseguro: {cipher_name}",
                            "severity": "MEDIUM",
                            "source":   "SSLAnalyzer",
                            "url":      self.target,
                        }
                        self.results["issues"].append(issue)
                        if self.context:
                            self.context.add_finding(issue)
                        print_status(f"Cipher fraco: {cipher_name}", "WARN")

                    # Certificado expirado
                    if cert:
                        not_after = cert.get("notAfter","")
                        if not_after:
                            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (exp - datetime.datetime.utcnow()).days
                            self.results["cert"] = {
                                "subject": dict(x[0] for x in cert.get("subject",[])),
                                "issuer":  dict(x[0] for x in cert.get("issuer",[])),
                                "expires": not_after,
                                "days_left": days_left,
                                "san": [v for _,v in cert.get("subjectAltName",[])],
                            }
                            if days_left < 0:
                                issue = {"issue": "Certificado SSL EXPIRADO",
                                         "severity": "CRITICAL", "source": "SSLAnalyzer", "url": self.target}
                                self.results["issues"].append(issue)
                                if self.context: self.context.add_finding(issue)
                                print_status(f"Cert EXPIRADO há {-days_left} dias!", "CRIT")
                            elif days_left < 30:
                                issue = {"issue": f"Certificado SSL expira em {days_left} dias",
                                         "severity": "MEDIUM", "source": "SSLAnalyzer", "url": self.target}
                                self.results["issues"].append(issue)
                                if self.context: self.context.add_finding(issue)
                                print_status(f"Cert expira em {days_left} dias.", "WARN")
                            else:
                                print_status(f"Cert válido por mais {days_left} dias.", "SUCCESS")

        except ssl.SSLError as e:
            issue = {"issue": f"Erro SSL: {e}", "severity": "HIGH",
                     "source": "SSLAnalyzer", "url": self.target}
            self.results["issues"].append(issue)
            if self.context: self.context.add_finding(issue)
            print_status(f"SSL Error: {e}", "ERROR")
        except Exception as e:
            print_status(f"SSL Analyzer: {e}", "WARN")

        return self.results
