"""
IDOR Tester — detecta Insecure Direct Object Reference em endpoints com IDs numéricos.
Compara respostas entre IDs diferentes para identificar acesso cruzado.
"""
import re, requests, warnings
from core.utils import print_status

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

ID_PATTERN = re.compile(r"(/(?:api|v\d|user|account|profile|order|item|post|doc|file|record)[s]?/?)(\d+)")


class IDORTester:
    def __init__(self, target: str, context=None):
        self.target  = target
        self.context = context
        self.results = []

    def _req(self, url):
        try:
            return requests.get(url, timeout=8, verify=False,
                                headers={"User-Agent": "Mozilla/5.0"})
        except Exception:
            return None

    def _extract_endpoints(self, pages: list) -> list[str]:
        endpoints = set()
        for page in pages:
            for match in ID_PATTERN.finditer(page["html"]):
                path  = match.group(1)
                id_   = match.group(2)
                full  = self.target.rstrip("/") + path + id_
                endpoints.add((full, path, id_))
            # Também no URL da própria página
            for match in ID_PATTERN.finditer(page["url"]):
                path = match.group(1)
                id_  = match.group(2)
                full = self.target.rstrip("/") + path + id_
                endpoints.add((full, path, id_))
        return list(endpoints)

    def test(self, pages: list) -> list:
        print_status("IDOR Testing em endpoints com IDs...", "INFO")
        endpoints = self._extract_endpoints(pages)
        tested = set()

        for (url, path, id_) in endpoints[:30]:  # limita a 30 endpoints
            if path in tested:
                continue
            tested.add(path)

            original = self._req(url)
            if not original or original.status_code != 200:
                continue

            # Testa IDs adjacentes: id-1, id+1, 0, 1
            for alt_id in [str(int(id_)-1), str(int(id_)+1), "0", "1", "9999"]:
                if alt_id == id_ or alt_id == "0":
                    continue
                alt_url = self.target.rstrip("/") + path + alt_id
                alt_r   = self._req(alt_url)

                if not alt_r:
                    continue

                # IDOR confirmado: resposta 200 com corpo diferente
                if (alt_r.status_code == 200
                        and len(alt_r.text) > 50
                        and alt_r.text != original.text):
                    finding = {
                        "url":      alt_url,
                        "original": url,
                        "issue":    f"Possível IDOR — ID {alt_id} retornou dados (tamanho {len(alt_r.text)})",
                        "severity": "HIGH",
                        "source":   "IDORTester",
                        "evidence": alt_r.text[:150],
                    }
                    self.results.append(finding)
                    if self.context:
                        self.context.add_finding(finding)
                    print_status(f"IDOR: {alt_url}", "CRIT")
                    break

        print_status(f"IDOR: {len(self.results)} achados.", "SUCCESS" if not self.results else "WARN")
        return self.results
