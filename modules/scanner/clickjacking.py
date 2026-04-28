"""
Clickjacking Tester — verifica X-Frame-Options, CSP frame-ancestors e testa na prática.
"""
import requests, warnings
from core.utils import print_status

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


class ClickjackingTester:
    def __init__(self, target: str, context=None):
        self.target  = target
        self.context = context

    def test(self) -> dict:
        print_status("Clickjacking check...", "INFO")
        result = {"url": self.target, "vulnerable": False, "details": {}}

        try:
            r = requests.get(self.target, timeout=8, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"})

            xfo = r.headers.get("X-Frame-Options", "")
            csp = r.headers.get("Content-Security-Policy", "")

            has_xfo          = bool(xfo)
            has_frame_anc    = "frame-ancestors" in csp
            is_vulnerable    = not has_xfo and not has_frame_anc

            result["details"] = {
                "X-Frame-Options":    xfo or "AUSENTE",
                "CSP frame-ancestors": "presente" if has_frame_anc else "AUSENTE",
            }

            if is_vulnerable:
                result["vulnerable"] = True
                finding = {
                    "url":      self.target,
                    "issue":    "Clickjacking — página pode ser embutida em iframe",
                    "severity": "MEDIUM",
                    "source":   "ClickjackingTester",
                    "evidence": "X-Frame-Options ausente e CSP sem frame-ancestors",
                }
                if self.context:
                    self.context.add_finding(finding)
                print_status("Clickjacking: página vulnerável.", "WARN")
            else:
                print_status("Clickjacking: protegido.", "SUCCESS")

        except Exception as e:
            print_status(f"Clickjacking: {e}", "ERROR")

        return result
