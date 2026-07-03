# 👁 Olho de Deus v3.0
### AI-Powered Pentest Framework | Eduardo Felype

> ⚠️ **USO EXCLUSIVO EM ALVOS AUTORIZADOS.**

---

## 🚀 Uso

```bash
# Instalação
pip install -r requirements.txt

# Scan completo (todos os pipelines)
python main.py http://target.com

# Só pipeline 1 (tradicional)
python main.py http://target.com --pipeline 1

# Com Shodan + VirusTotal
python main.py http://target.com --shodan SUA_KEY --vt SUA_KEY

# Sem pipeline agressivo
python main.py http://target.com --no-aggressive
```

---

## 🏗️ Arquitetura — 3 Pipelines

```
Pipeline 1 — TRADICIONAL
  recon passivo (WHOIS, DNS, SSL, dorks, crt.sh)
  → recon ativo (Nmap, Gobuster)
  → subdomain enumeration + takeover check
  → OSINT (Shodan/InternetDB + urlscan.io)
  → scanner (Nikto, CORS, Open Redirect, CVEs)

Pipeline 2 — AGRESSIVO
  WAF fingerprinting
  → crawler profundo (robots.txt, sitemap, JS files, forms)
  → motor agressivo (JS endpoints, path traversal, paths sensíveis)
  → API fuzzer (verb tampering, endpoints expostos)
  → GraphQL (introspection, unauth, DoS)
  → clickjacking + rate limit
  → plugins (headers, cookies, CSP)

Pipeline 3 — IA
  JWT analyzer (alg:none, segredo fraco, claims sensíveis)
  → IDOR tester
  → AI Engine:
      secret scanner (12+ padrões)
      smart analyzer (heurísticas)
      exploiter (XSS, SQLi, SSRF, forms)
      priorização inteligente (Risk Engine)
      learning engine (memória histórica)
      insights automáticos
  → CVE lookup por tech detectada
  → PDF Report + HTML Dashboard
```

---

## 📦 Módulos

| Módulo | Descrição |
|--------|-----------|
| `recon/recon.py` | WHOIS, DNS, SSL, Google Dorks |
| `recon/active.py` | Nmap, Gobuster, headers |
| `recon/subdomain_enum.py` | DNS brute + crt.sh + takeover check |
| `scanner/waf_detector.py` | Cloudflare, AWS WAF, ModSecurity, Akamai... |
| `scanner/ssl_analyzer.py` | Protocolo fraco, cipher, expiração |
| `scanner/jwt_analyzer.py` | alg:none, segredo fraco, claims |
| `scanner/graphql_tester.py` | Introspection, unauth, DoS |
| `scanner/idor_tester.py` | IDOR por variação de ID |
| `scanner/clickjacking.py` | X-Frame-Options, CSP frame-ancestors |
| `scanner/rate_limit_tester.py` | Endpoints de auth sem rate limit |
| `scanner/api_fuzzer.py` | Endpoints JS, verb tampering |
| `scanner/osint_enricher.py` | Shodan/InternetDB, urlscan.io/VT |
| `aggressive/crawler.py` | Crawler com robots, sitemap, JS, forms |
| `aggressive/aggressive_engine.py` | Path traversal, paths sensíveis, JS endpoints |
| `ai/ai_engine.py` | Secret scanner, XSS/SQLi/SSRF, priorização |
| `ai/risk_engine.py` | Score multi-critério |
| `ai/learning_engine.py` | Memória histórica JSON |
| `plugins/` | Headers, cookies, CSP |
| `reports/report.py` | PDF profissional + HTML Dashboard |

---

## 📊 Outputs

- `reports/<target>_report.json` — dados completos em JSON
- `reports/<target>_report.pdf` — relatório técnico com gráficos, CVSS, recomendações
- `reports/<target>_dashboard.html` — dashboard interativo com Chart.js
- `data/results.db` — SQLite com histórico de findings
- `data/ai_memory.json` — memória da IA entre sessões
