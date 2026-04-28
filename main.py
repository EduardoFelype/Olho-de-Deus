"""
Olho de Deus v3.0 — AI-Powered Pentest Framework
Eduardo Felype

Uso: python main.py http://target.com [--shodan KEY] [--vt KEY]
"""
import sys, json, argparse
from colorama import init
from urllib.parse import urlparse
from config import Config
from core.banner import show_banner
from core.utils import print_status
from core.shared_context import SharedContext

# Pipelines
from modules.recon.recon import run_recon, PassiveRecon
from modules.recon.active import ActiveRecon
from modules.recon.subdomain_enum import SubdomainEnumerator

from modules.scanner.scanner import Scanner
from modules.scanner.waf_detector import WAFDetector
from modules.scanner.jwt_analyzer import JWTAnalyzer
from modules.scanner.graphql_tester import GraphQLTester
from modules.scanner.idor_tester import IDORTester
from modules.scanner.clickjacking import ClickjackingTester
from modules.scanner.osint_enricher import OSINTEnricher
from modules.scanner.ssl_analyzer import SSLAnalyzer
from modules.scanner.rate_limit_tester import RateLimitTester
from modules.scanner.api_fuzzer import APIFuzzer

from modules.aggressive.crawler import Crawler
from modules.aggressive.aggressive_engine import AggressiveEngine

from modules.plugins.loader import load_plugins
from modules.ai.ai_engine import run_ai

from reports.report import generate_pdf, generate_dashboard

init(autoreset=True)


def parse_args():
    p = argparse.ArgumentParser(description="Olho de Deus v3 — AI-Powered Pentest")
    p.add_argument("target",          help="URL alvo (ex: http://site.com)")
    p.add_argument("--shodan",        default="", help="Shodan API Key (opcional)")
    p.add_argument("--vt",            default="", help="VirusTotal API Key (opcional)")
    p.add_argument("--pipeline",      default="all", choices=["1","2","3","all"],
                   help="Pipeline: 1=tradicional, 2=agressivo, 3=IA, all=todos")
    p.add_argument("--no-aggressive", action="store_true", help="Pula pipeline agressivo")
    return p.parse_args()


def save_results(full_results: dict, target: str):
    Config.ensure_dirs()
    base = urlparse(target).netloc.replace(".", "_") or "target"

    json_file = f"{Config.REPORT_DIR}/{base}_report.json"
    pdf_file  = f"{Config.REPORT_DIR}/{base}_report.pdf"
    html_file = f"{Config.REPORT_DIR}/{base}_dashboard.html"

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(full_results, f, indent=2, ensure_ascii=False, default=str)

    generate_pdf(full_results, pdf_file)
    generate_dashboard(full_results, html_file)

    print_status(f"JSON      → {json_file}", "SUCCESS")
    print_status(f"PDF       → {pdf_file}", "SUCCESS")
    print_status(f"Dashboard → {html_file}", "SUCCESS")


def main():
    show_banner()
    args   = parse_args()
    target = args.target
    if not target.startswith("http"):
        target = "http://" + target

    Config.ensure_dirs()
    context         = SharedContext()
    context.target  = target
    context.init_db()
    context.add_url(target)

    domain = urlparse(target).netloc

    print_status(f"Alvo: {target}", "CRIT")
    print_status(f"Pipeline: {args.pipeline}", "INFO")

    full = {"target": target}

    # ══════════════════════════════════════════════════════
    # PIPELINE 1 — TRADICIONAL: Recon → Scanner → Relatório
    # ══════════════════════════════════════════════════════
    if args.pipeline in ("1", "all"):
        print_status("", "INFO")
        print_status("━━━ PIPELINE 1: TRADICIONAL ━━━━━━━━━━━━━━━━━━━━━━━━", "CRIT")

        print_status("[1/6] Recon Passivo", "INFO")
        pr = PassiveRecon(target)
        full["passive"] = pr.execute_all()

        print_status("[2/6] Recon Ativo (Nmap + Gobuster)", "INFO")
        ar = ActiveRecon(target)
        full["active"] = ar.execute_all()

        print_status("[3/6] SSL/TLS Analysis", "INFO")
        ssl_a = SSLAnalyzer(target, context)
        full["ssl"] = ssl_a.analyze()

        print_status("[4/6] Subdomain Enumeration", "INFO")
        sub = SubdomainEnumerator(domain, context)
        full["subdomains"] = sub.run()

        print_status("[5/6] OSINT Enrichment", "INFO")
        osint = OSINTEnricher(target, args.shodan, args.vt)
        full["osint"] = osint.run()

        print_status("[6/6] Scanner (Nikto + CORS + Open Redirect)", "INFO")
        sc = Scanner(target)
        full["scanner"] = sc.execute_all()

    # ══════════════════════════════════════════════════════
    # PIPELINE 2 — AGRESSIVO: Discovery → Crawler → Plugins
    # ══════════════════════════════════════════════════════
    if args.pipeline in ("2", "all") and not args.no_aggressive:
        print_status("", "INFO")
        print_status("━━━ PIPELINE 2: AGRESSIVO ━━━━━━━━━━━━━━━━━━━━━━━━━━", "CRIT")

        print_status("[1/8] WAF Fingerprinting", "INFO")
        waf = WAFDetector(target)
        full["waf"] = waf.probe()

        print_status("[2/8] Crawler profundo", "INFO")
        crawler = Crawler(target, context=context)
        pages   = crawler.crawl()
        context.add_pages(pages)
        full["crawled_pages"] = len(pages)

        print_status("[3/8] Motor Agressivo (JS endpoints + Path Traversal + Paths sensíveis)", "INFO")
        agg = AggressiveEngine(target, context)
        full["aggressive"] = agg.run(pages)

        print_status("[4/8] API Fuzzer", "INFO")
        api_fuzz = APIFuzzer(target, context)
        full["api_fuzzer"] = api_fuzz.run(pages)

        print_status("[5/8] GraphQL Tester", "INFO")
        gql = GraphQLTester(target, context)
        full["graphql"] = gql.run()

        print_status("[6/8] Clickjacking Tester", "INFO")
        cj = ClickjackingTester(target, context)
        full["clickjacking"] = cj.test()

        print_status("[7/8] Rate Limit Tester", "INFO")
        rl = RateLimitTester(target, context)
        full["rate_limit"] = rl.test()

        print_status("[8/8] Plugins", "INFO")
        plugins = load_plugins()
        plugin_findings = []
        from core.utils import safe_request
        r_main = safe_request(target)
        if r_main:
            for plugin in plugins:
                result = plugin.run(target, r_main)
                if result:
                    plugin_findings.append(result)
                    context.add_finding({**result, "source": f"Plugin:{plugin.name}"})
        full["plugins"] = plugin_findings

    # ══════════════════════════════════════════════════════
    # PIPELINE 3 — IA: Análise global → Priorização → Insights
    # ══════════════════════════════════════════════════════
    if args.pipeline in ("3", "all"):
        print_status("", "INFO")
        print_status("━━━ PIPELINE 3: IA ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "CRIT")

        pages = context.pages or []

        print_status("[1/5] JWT Analyzer", "INFO")
        jwt = JWTAnalyzer()
        full["jwt"] = jwt.scan_pages(pages)

        print_status("[2/5] IDOR Tester", "INFO")
        idor = IDORTester(target, context)
        full["idor"] = idor.test(pages)

        print_status("[3/5] CVE Lookup por tecnologia", "INFO")
        techs_so_far = full.get("scanner", {}).get("technologies", [])

        print_status("[4/5] AI Engine (Secrets + Smart Analysis + Exploiter + Priorização)", "INFO")
        active_headers = full.get("active", {}).get("headers", {})
        ai_results = run_ai(target, context, pages, active_headers)

        full["technologies"]       = ai_results.get("technologies", [])
        full["secrets"]            = ai_results.get("secrets", [])
        full["smart_analysis"]     = ai_results.get("smart_analysis", [])
        full["exploitation"]       = ai_results.get("exploitation", [])
        full["ai_insights"]        = ai_results.get("insights", [])
        full["ai_top_issues"]      = ai_results.get("top_issues", [])
        full["findings_prioritized"] = ai_results.get("prioritized", [])

        # CVEs por tech detectada
        if full["technologies"]:
            sc2 = Scanner(target)
            full["cve_matches"] = sc2.cve_lookup(full["technologies"]) if hasattr(sc2,"cve_lookup") else []
        else:
            full["cve_matches"] = []

        print_status("[5/5] Gerando Relatórios (PDF + Dashboard HTML)", "INFO")

    # ══════════════════════════════════════════════════════
    # RELATÓRIO FINAL
    # ══════════════════════════════════════════════════════
    print_status("", "INFO")
    print_status("━━━ GERANDO RELATÓRIOS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "CRIT")

    # Garante que findings_prioritized existe
    if "findings_prioritized" not in full:
        from modules.ai.risk_engine import RiskEngine
        risk = RiskEngine()
        full["findings_prioritized"] = risk.prioritize(context.all_findings())[:60]

    if "secrets" not in full:
        full["secrets"] = []
    if "technologies" not in full:
        full["technologies"] = []
    if "ai_insights" not in full:
        full["ai_insights"] = []
    if "ai_top_issues" not in full:
        full["ai_top_issues"] = []
    if "cve_matches" not in full:
        full["cve_matches"] = []

    save_results(full, target)

    # Resumo final
    total = len(full["findings_prioritized"])
    crit  = sum(1 for f in full["findings_prioritized"] if f.get("severity","").upper()=="CRITICAL")
    high  = sum(1 for f in full["findings_prioritized"] if f.get("severity","").upper()=="HIGH")

    print_status("", "INFO")
    print_status(f"VARREDURA FINALIZADA — {total} findings ({crit} críticos, {high} altos)", "SUCCESS")
    if full.get("ai_insights"):
        print_status("INSIGHTS DA IA:", "WARN")
        for ins in full["ai_insights"]:
            print_status(ins, "WARN")


if __name__ == "__main__":
    main()
