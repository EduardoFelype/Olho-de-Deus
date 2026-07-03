"""
OSINT Enricher — Shodan lookup por IP + VirusTotal domain check.
Requer API keys opcionais definidas em config. Sem key, faz lookup público limitado.
"""
import socket, requests, warnings
from urllib.parse import urlparse
from core.utils import print_status

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


class OSINTEnricher:
    def __init__(self, target: str, shodan_key: str = "", vt_key: str = ""):
        self.target      = target
        self.domain      = urlparse(target).netloc or target
        self.shodan_key  = shodan_key
        self.vt_key      = vt_key
        self.results     = {"ip": "", "shodan": {}, "virustotal": {}, "headers_exposed": {}}

    def resolve_ip(self):
        try:
            self.results["ip"] = socket.gethostbyname(self.domain)
            print_status(f"IP resolvido: {self.results['ip']}", "INFO")
        except Exception:
            pass

    def shodan_lookup(self):
        if not self.results["ip"]:
            return
        ip = self.results["ip"]

        if self.shodan_key:
            try:
                r = requests.get(
                    f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}",
                    timeout=10
                )
                if r.status_code == 200:
                    data = r.json()
                    self.results["shodan"] = {
                        "org":      data.get("org",""),
                        "isp":      data.get("isp",""),
                        "country":  data.get("country_name",""),
                        "ports":    data.get("ports",[]),
                        "vulns":    list(data.get("vulns",{}).keys()),
                        "os":       data.get("os",""),
                        "hostnames": data.get("hostnames",[]),
                    }
                    vulns = self.results["shodan"]["vulns"]
                    if vulns:
                        print_status(f"Shodan: {len(vulns)} CVEs no IP — {vulns[:5]}", "CRIT")
                    else:
                        print_status(f"Shodan: {ip} — ports {self.results['shodan']['ports']}", "SUCCESS")
            except Exception as e:
                print_status(f"Shodan API: {e}", "WARN")
        else:
            # Sem key: lookup público básico via InternetDB (sem autenticação)
            try:
                r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=8)
                if r.status_code == 200:
                    data = r.json()
                    self.results["shodan"] = {
                        "ports":  data.get("ports",[]),
                        "vulns":  data.get("vulns",[]),
                        "tags":   data.get("tags",[]),
                        "source": "InternetDB (público)",
                    }
                    vulns = self.results["shodan"]["vulns"]
                    if vulns:
                        print_status(f"InternetDB: {len(vulns)} CVEs no IP!", "CRIT")
                    else:
                        print_status(f"InternetDB: ports {data.get('ports',[][:8])}", "INFO")
            except Exception as e:
                print_status(f"InternetDB: {e}", "WARN")

    def virustotal_lookup(self):
        if not self.vt_key:
            # Sem key: verifica reputação pública via urlscan.io
            try:
                r = requests.get(
                    f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=5",
                    timeout=10
                )
                if r.status_code == 200:
                    data  = r.json()
                    total = data.get("total", 0)
                    scans = data.get("results", [])
                    self.results["virustotal"] = {
                        "source": "urlscan.io",
                        "scans":  total,
                        "last_scan": scans[0].get("task",{}).get("time","") if scans else "",
                        "verdicts":  [s.get("verdicts",{}).get("overall",{}).get("malicious",False) for s in scans],
                    }
                    malicious = sum(self.results["virustotal"]["verdicts"])
                    if malicious:
                        print_status(f"urlscan.io: {malicious} scans marcados como malicioso!", "CRIT")
                    else:
                        print_status(f"urlscan.io: {total} scans, sem flags maliciosas.", "SUCCESS")
            except Exception as e:
                print_status(f"urlscan.io: {e}", "WARN")
            return

        # Com key do VirusTotal
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{self.domain}",
                headers={"x-apikey": self.vt_key}, timeout=10
            )
            if r.status_code == 200:
                attrs = r.json().get("data",{}).get("attributes",{})
                stats = attrs.get("last_analysis_stats",{})
                self.results["virustotal"] = {
                    "malicious":   stats.get("malicious",0),
                    "suspicious":  stats.get("suspicious",0),
                    "harmless":    stats.get("harmless",0),
                    "reputation":  attrs.get("reputation",0),
                    "categories":  attrs.get("categories",{}),
                }
                mal = self.results["virustotal"]["malicious"]
                if mal > 0:
                    print_status(f"VirusTotal: {mal} engines marcam como MALICIOSO!", "CRIT")
                else:
                    print_status("VirusTotal: domínio limpo.", "SUCCESS")
        except Exception as e:
            print_status(f"VirusTotal: {e}", "WARN")

    def check_server_exposure(self):
        """Verifica informações sensíveis expostas nos headers do servidor."""
        try:
            r = requests.get(self.target, timeout=8, verify=False)
            exposed = {}
            for h in ["Server","X-Powered-By","X-AspNet-Version","X-Generator",
                      "X-Drupal-Cache","X-Wordpress-Version","Via","X-Backend"]:
                val = r.headers.get(h,"")
                if val:
                    exposed[h] = val
            if exposed:
                self.results["headers_exposed"] = exposed
                print_status(f"Headers de versão expostos: {list(exposed.keys())}", "WARN")
        except Exception:
            pass

    def run(self):
        print_status("OSINT Enrichment...", "INFO")
        self.resolve_ip()
        self.shodan_lookup()
        self.virustotal_lookup()
        self.check_server_exposure()
        return self.results
