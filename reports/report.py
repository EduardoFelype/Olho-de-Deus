"""
Report Generator — PDF profissional + HTML Dashboard interativo.
Chamado ao final dos 3 pipelines com o full_results consolidado.
"""
import json, datetime, os
from config import Config

# ─── PDF ──────────────────────────────────────────────────────────────────────
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

C_RED    = colors.HexColor("#e63946")
C_ORANGE = colors.HexColor("#f4a261")
C_YELLOW = colors.HexColor("#e9c46a")
C_GREEN  = colors.HexColor("#2a9d8f")
C_BLUE   = colors.HexColor("#457b9d")
C_DARK   = colors.HexColor("#1a1a2e")
C_GRAY   = colors.HexColor("#adb5bd")

SEV_COLORS = {"CRITICAL":C_RED,"HIGH":C_ORANGE,"MEDIUM":C_YELLOW,"LOW":C_GREEN,"INFO":C_BLUE}

CVSS_MAP  = {
    "SQLi Error-Based":9.8,"SQLi":9.8,"SQLi (HTTP 500)":7.5,
    "XSS Refletido":6.1,"XSS em Form":6.1,"XSS":6.1,
    "Possível SSRF":8.6,"SSRF":8.6,"Path Traversal":7.5,
    "Secret exposto":9.0,"CORS":6.5,"Open Redirect":6.1,
    "CRITICAL":9.0,"HIGH":7.5,"MEDIUM":5.0,"LOW":2.5,
}
IMPACT_MAP = {
    "sqli":      "Acesso completo ao banco. Possível escalada para RCE.",
    "xss":       "Roubo de sessão, defacement, phishing direcionado.",
    "ssrf":      "Acesso a serviços internos e metadata de cloud.",
    "secret":    "Comprometimento de APIs, infraestrutura e autenticação.",
    "traversal": "Leitura de arquivos arbitrários no servidor.",
    "cors":      "Leitura cross-origin de dados autenticados.",
    "redirect":  "Phishing e bypass de controles de acesso.",
    "default":   "Avaliar impacto conforme contexto da aplicação.",
}
REC_MAP = {
    "sqli":      "Usar prepared statements. Nunca concatenar inputs em queries.",
    "xss":       "Sanitizar outputs. Implementar CSP restritiva.",
    "ssrf":      "Whitelist de URLs permitidas. Bloquear ranges privados.",
    "secret":    "Remover do código. Usar variáveis de ambiente e secret managers.",
    "traversal": "Validar e sanitizar caminhos. Usar chroot/jail quando possível.",
    "cors":      "Restringir Access-Control-Allow-Origin a origens confiáveis.",
    "redirect":  "Validar destinos de redirecionamento contra whitelist.",
    "default":   "Revisar e corrigir conforme contexto.",
}

def _style(size=9, color=colors.black, bold=False, align=TA_CENTER, font=None):
    return ParagraphStyle("s", fontSize=size, textColor=color,
                          alignment=align, fontName=font or ("Helvetica-Bold" if bold else "Helvetica"))

def _badge(sev):
    c = {"CRITICAL":"#e63946","HIGH":"#f4a261","MEDIUM":"#e9c46a","LOW":"#2a9d8f","INFO":"#457b9d"}
    return f'<font color="{c.get(sev.upper(),"#999")}"><b>[{sev.upper()}]</b></font>'

def _score(report):
    s = 10.0
    for f in report.get("findings_prioritized",[]):
        s -= {"CRITICAL":2.5,"HIGH":1.5,"MEDIUM":0.7,"LOW":0.2}.get(f.get("severity","").upper(),0)
    if report.get("secrets"): s -= 2.0
    return round(max(s,0),1)

def _counts(report):
    c = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in report.get("findings_prioritized",[]):
        c[f.get("severity","INFO").upper()] = c.get(f.get("severity","INFO").upper(),0)+1
    for _ in report.get("secrets",[]): c["CRITICAL"]+=1
    return c

def _pie(counts):
    labels = [k for k,v in counts.items() if v>0]
    vals   = [counts[k] for k in labels]
    if not vals:
        d = Drawing(200,150)
        d.add(String(100,75,"Sem findings",textAnchor="middle",fontSize=10,fillColor=C_GRAY))
        return d
    d   = Drawing(220,160)
    pie = Pie()
    pie.x=10; pie.y=10; pie.width=140; pie.height=140
    pie.data=vals; pie.labels=[f"{l}({v})" for l,v in zip(labels,vals)]
    pie.sideLabels=True; pie.slices.strokeWidth=0.5
    for i,l in enumerate(labels):
        pie.slices[i].fillColor = SEV_COLORS.get(l,C_BLUE)
    d.add(pie)
    return d

def _scorebar(score):
    d = Drawing(400,40)
    fill = C_RED if score<4 else (C_ORANGE if score<7 else C_GREEN)
    d.add(Rect(0,10,360,20,fillColor=colors.HexColor("#dddddd"),strokeColor=None))
    if score>0: d.add(Rect(0,10,int(360*score/10),20,fillColor=fill,strokeColor=None))
    d.add(String(368,18,f"{score}/10",fontSize=11,fontName="Helvetica-Bold",fillColor=fill))
    return d

def _impact(f):
    text = (f.get("issue","") + f.get("type","")).lower()
    for k,v in IMPACT_MAP.items():
        if k in text: return v
    return IMPACT_MAP["default"]

def _rec(f):
    text = (f.get("issue","") + f.get("type","")).lower()
    for k,v in REC_MAP.items():
        if k in text: return v
    return REC_MAP["default"]

def generate_pdf(report, filename="report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=(21*cm,29.7*cm),
                            rightMargin=1.8*cm,leftMargin=1.8*cm,
                            topMargin=1.5*cm,bottomMargin=1.5*cm)
    now    = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    target = report.get("target","N/A")
    score  = _score(report)
    counts = _counts(report)
    total  = sum(counts.values())
    C = []

    # CAPA
    C.append(Spacer(1,1.2*cm))
    C.append(Paragraph("👁  OLHO DE DEUS", _style(26,C_RED,True,TA_CENTER)))
    C.append(Paragraph("Relatório Técnico de Segurança — AI-Powered Pentest", _style(11,C_GRAY,align=TA_CENTER)))
    C.append(HRFlowable(width="100%",thickness=2,color=C_RED,spaceAfter=10))
    C.append(Paragraph(f"<b>Alvo:</b> {target}",_style(10)))
    C.append(Paragraph(f"<b>Data:</b> {now}",_style(10)))
    C.append(Paragraph(f"<b>Total de findings:</b> {total}",_style(10)))
    C.append(Spacer(1,.5*cm))
    C.append(Paragraph("Security Score",_style(13,C_RED,True)))
    C.append(renderPDF.GraphicsFlowable(_scorebar(score)))
    lbl = ("CRÍTICO — Ação imediata" if score<4 else
           "ATENÇÃO — Vulnerabilidades significativas" if score<7 else "BOM — Poucos problemas")
    C.append(Paragraph(lbl,_style(9,C_GRAY)))
    C.append(Spacer(1,.6*cm))

    # RESUMO
    C.append(Paragraph("Resumo Executivo",_style(14,C_RED,True)))
    rows = [["Severidade","Qtd","Prazo"]]
    for sev,prazo in [("CRITICAL","Imediato"),("HIGH","≤ 7 dias"),("MEDIUM","≤ 30 dias"),("LOW","Próx. ciclo")]:
        if counts[sev]>0:
            rows.append([Paragraph(_badge(sev),_style(9)),str(counts[sev]),prazo])
    if len(rows)>1:
        t=Table(rows,colWidths=[5*cm,3*cm,5*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
            ("GRID",(0,0),(-1,-1),.5,C_GRAY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f8f9fa")]),
        ]))
        C.append(t)
    C.append(Spacer(1,.5*cm))
    C.append(Paragraph("Distribuição por Severidade",_style(13,C_RED,True)))
    C.append(renderPDF.GraphicsFlowable(_pie(counts)))
    C.append(PageBreak())

    # AI INSIGHTS
    insights = report.get("ai_insights",[])
    if insights:
        C.append(Paragraph("🤖 Insights da IA",_style(14,C_RED,True)))
        for ins in insights:
            C.append(Paragraph(f"▸ {ins}",_style(9)))
        C.append(Spacer(1,.5*cm))

    # TOP ISSUES HISTÓRICOS
    top = report.get("ai_top_issues",[])
    if top:
        C.append(Paragraph("Issues mais recorrentes (memória histórica)",_style(12,C_RED,True)))
        rows=[["Issue","Ocorrências"]]
        for item in top[:8]:
            rows.append([item.get("issue",""),str(item.get("count",0))])
        t=Table(rows,colWidths=[11*cm,3*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
            ("GRID",(0,0),(-1,-1),.5,C_GRAY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f8f9fa")]),
        ]))
        C.append(t)
        C.append(Spacer(1,.5*cm))

    # FINDINGS CRÍTICOS DETALHADOS
    prioritized = report.get("findings_prioritized",[])
    crit_high   = [f for f in prioritized if f.get("severity","").upper() in ("CRITICAL","HIGH")]
    if crit_high:
        C.append(Paragraph("🔴 Vulnerabilidades Críticas e Altas",_style(14,C_RED,True)))
        for i,f in enumerate(crit_high[:25],1):
            sev   = f.get("severity","INFO").upper()
            issue = f.get("issue") or f.get("type","Desconhecido")
            url   = f.get("url",target)
            cvss  = CVSS_MAP.get(issue, CVSS_MAP.get(sev,5.0))
            ev    = f.get("evidence","") or f.get("payload","") or f.get("value","")
            block=[
                Paragraph(f"{i}. {_badge(sev)} {issue}",_style(10,bold=True)),
                Paragraph(f"<b>URL:</b> {url[:90]}",_style(9)),
                Paragraph(f"<b>CVSS estimado:</b> {cvss}",_style(9)),
                Paragraph(f"<b>Impacto:</b> {_impact(f)}",_style(9)),
                Paragraph(f"<b>Recomendação:</b> {_rec(f)}",_style(9)),
            ]
            if ev:
                block.append(Paragraph(f"<b>Evidência:</b> {str(ev)[:120]}",
                                       _style(8,colors.HexColor("#2d6a4f"),font="Courier")))
            block.append(HRFlowable(width="100%",thickness=.5,color=C_GRAY,spaceAfter=4))
            C.append(KeepTogether(block))
    C.append(PageBreak())

    # SECRETS
    secrets = report.get("secrets",[])
    if secrets:
        C.append(Paragraph("🔑 Secrets e Credenciais Expostos",_style(14,C_RED,True)))
        rows=[["Tipo","Valor (truncado)","URL"]]
        for s in secrets[:30]:
            rows.append([s.get("type",""),str(s.get("value",""))[:40]+"…",s.get("url","")[:55]])
        t=Table(rows,colWidths=[4.5*cm,5.5*cm,7.5*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_RED),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
            ("GRID",(0,0),(-1,-1),.5,C_GRAY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#fff5f5"),colors.white]),
        ]))
        C.append(t)
        C.append(Spacer(1,.5*cm))

    # TECNOLOGIAS + CVEs
    techs = report.get("technologies",[])
    cves  = report.get("cve_matches",[])
    if techs:
        C.append(Paragraph("🧩 Stack Tecnológico e CVEs",_style(14,C_RED,True)))
        C.append(Paragraph("  •  ".join(techs),_style(9)))
        if cves:
            C.append(Spacer(1,.3*cm))
            rows=[["CVE","Tech","Severidade","Descrição"]]
            for cv in (cves or [])[:15]:
                rows.append([cv.get("cve",""),cv.get("tech",""),
                             cv.get("severity",""),cv.get("desc","")[:50]])
            t=Table(rows,colWidths=[3*cm,3*cm,2.5*cm,9*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                ("GRID",(0,0),(-1,-1),.5,C_GRAY),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f8f9fa")]),
            ]))
            C.append(t)
        C.append(Spacer(1,.5*cm))

    # RECOMENDAÇÕES GERAIS
    C.append(Paragraph("📋 Recomendações Gerais",_style(14,C_RED,True)))
    recs=[
        "Implementar WAF na frente da aplicação.",
        "Habilitar todos os security headers (CSP, HSTS, X-Frame-Options, etc.).",
        "Remover secrets do frontend. Usar variáveis de ambiente e secret managers.",
        "Adotar prepared statements em todas as queries SQL.",
        "Implementar rate limiting em endpoints de autenticação.",
        "Manter dependências atualizadas com patches de segurança.",
        "Configurar monitoramento de logs com alertas para padrões de ataque.",
        "Realizar pentest manual focado nos findings críticos deste relatório.",
    ]
    for r in recs:
        C.append(Paragraph(f"  ▸  {r}",_style(9)))

    C.append(Spacer(1,1*cm))
    C.append(HRFlowable(width="100%",thickness=1,color=C_RED))
    C.append(Spacer(1,.3*cm))
    C.append(Paragraph(f"Gerado por <b>Olho de Deus v3</b> — Eduardo Felype | {now}",
                       _style(8,C_GRAY,align=TA_CENTER)))
    doc.build(C)


# ─── HTML DASHBOARD ──────────────────────────────────────────────────────────
def generate_dashboard(report, filename="dashboard.html"):
    now    = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    target = report.get("target","N/A")
    score  = _score(report)
    counts = _counts(report)

    findings_prioritized = report.get("findings_prioritized",[])
    secrets   = report.get("secrets",[])
    techs     = report.get("technologies",[])
    insights  = report.get("ai_insights",[])
    top_issues= report.get("ai_top_issues",[])
    cves      = report.get("cve_matches",[])

    score_color = "#e63946" if score<4 else ("#f4a261" if score<7 else "#2a9d8f")
    score_label = "CRÍTICO" if score<4 else ("ATENÇÃO" if score<7 else "BOM")

    def badge(sev):
        c = {"CRITICAL":"#e63946","HIGH":"#f4a261","MEDIUM":"#e9c46a","LOW":"#2a9d8f","INFO":"#457b9d"}
        return f'<span class="badge" style="background:{c.get(sev.upper(),"#666")}">{sev}</span>'

    def cvss_val(f):
        issue = f.get("issue","") or f.get("type","")
        sev   = f.get("severity","LOW").upper()
        for k,v in CVSS_MAP.items():
            if k.lower() in issue.lower(): return v
        return CVSS_MAP.get(sev,5.0)

    # Findings rows
    finding_rows = ""
    for f in findings_prioritized[:60]:
        sev   = f.get("severity","INFO").upper()
        issue = f.get("issue") or f.get("type","")
        url   = f.get("url","")
        ev    = str(f.get("evidence","") or f.get("payload","") or f.get("value",""))[:80]
        src   = f.get("source","")
        cvss  = cvss_val(f)
        finding_rows += f"""
        <tr class="finding-row" data-sev="{sev}">
          <td>{badge(sev)}</td>
          <td>{issue}</td>
          <td><a href="{url}" target="_blank">{url[:60]}…</a></td>
          <td>{cvss}</td>
          <td class="ev">{ev}</td>
          <td><span class="source">{src}</span></td>
        </tr>"""

    secret_rows = ""
    for s in secrets[:30]:
        secret_rows += f"""
        <tr>
          <td><span class="badge" style="background:#e63946">{s.get('type','')}</span></td>
          <td class="ev">{str(s.get('value',''))[:60]}…</td>
          <td><a href="{s.get('url','')}" target="_blank">{s.get('url','')[:60]}</a></td>
        </tr>"""

    insight_items = "".join(f"<li>{i}</li>" for i in insights)
    top_items     = "".join(
        f"<div class='top-item'><span>{i['issue']}</span><b>{i['count']}x</b></div>"
        for i in top_issues
    )
    tech_badges = "".join(f"<span class='tech-badge'>{t}</span>" for t in techs)

    cve_rows = ""
    for cv in (cves or [])[:15]:
        sc = {"CRITICAL":"#e63946","HIGH":"#f4a261","MEDIUM":"#e9c46a"}.get(cv.get("severity",""), "#adb5bd")
        cve_rows += f"""
        <tr>
          <td><a href="https://nvd.nist.gov/vuln/detail/{cv.get('cve','')}" target="_blank">{cv.get('cve','')}</a></td>
          <td>{cv.get('tech','')}</td>
          <td><span class="badge" style="background:{sc}">{cv.get('severity','')}</span></td>
          <td>{cv.get('desc','')}</td>
        </tr>"""

    pie_data    = json.dumps([counts[k] for k in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]])
    top_labels  = json.dumps([i["issue"][:30] for i in top_issues])
    top_vals    = json.dumps([i["count"] for i in top_issues])

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Olho de Deus — Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  :root {{
    --bg:#0d0d1a; --panel:#12122a; --border:#1e1e3a;
    --red:#e63946; --orange:#f4a261; --yellow:#e9c46a;
    --green:#2a9d8f; --blue:#457b9d; --gray:#adb5bd; --white:#f1faee;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--white);font-family:'Segoe UI',sans-serif;font-size:14px}}
  header{{background:var(--panel);border-bottom:2px solid var(--red);padding:18px 32px;display:flex;align-items:center;gap:16px}}
  header h1{{font-size:22px;color:var(--red);letter-spacing:2px}}
  header span{{color:var(--gray);font-size:13px}}
  .meta{{margin-left:auto;text-align:right;font-size:12px;color:var(--gray)}}
  main{{padding:24px 32px;display:grid;gap:20px}}
  .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px}}
  .card{{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px;text-align:center}}
  .card .num{{font-size:36px;font-weight:700;line-height:1}}
  .card .lbl{{font-size:11px;color:var(--gray);margin-top:4px;text-transform:uppercase;letter-spacing:1px}}
  .card.crit{{border-color:var(--red)}} .card.crit .num{{color:var(--red)}}
  .card.high{{border-color:var(--orange)}} .card.high .num{{color:var(--orange)}}
  .card.med{{border-color:var(--yellow)}} .card.med .num{{color:var(--yellow)}}
  .card.low{{border-color:var(--green)}} .card.low .num{{color:var(--green)}}
  .card.score .num{{color:{score_color}}}
  .charts{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
  .box{{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:20px}}
  .box h3{{color:var(--red);font-size:13px;letter-spacing:1px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:8px}}
  canvas{{max-height:260px}}
  .insights ul{{list-style:none;display:grid;gap:8px}}
  .insights li{{background:#1a1a2e;border-left:3px solid var(--red);padding:10px 14px;border-radius:4px;font-size:13px}}
  .filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}}
  .filter-btn{{background:var(--panel);border:1px solid var(--border);color:var(--gray);
               padding:5px 14px;border-radius:20px;cursor:pointer;font-size:12px;transition:.2s}}
  .filter-btn.active,.filter-btn:hover{{border-color:var(--red);color:var(--white)}}
  table{{width:100%;border-collapse:collapse;font-size:12px}}
  th{{background:#1a1a2e;color:var(--gray);padding:8px 10px;text-align:left;font-size:11px;letter-spacing:.5px;text-transform:uppercase}}
  td{{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
  tr:hover td{{background:#14142a}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff}}
  .source{{font-size:10px;color:var(--gray);background:#1a1a2e;padding:2px 6px;border-radius:3px}}
  .ev{{font-family:monospace;font-size:11px;color:#7ec8a0;word-break:break-all}}
  a{{color:var(--blue);text-decoration:none}} a:hover{{text-decoration:underline}}
  .tech-badge{{background:#1a1a2e;border:1px solid var(--border);padding:4px 10px;border-radius:12px;font-size:12px;margin:3px;display:inline-block}}
  .top-item{{display:flex;justify-content:space-between;padding:8px 12px;background:#1a1a2e;border-radius:6px;margin-bottom:6px;font-size:12px}}
  .top-item b{{color:var(--red)}}
  .score-bar-wrap{{margin:8px 0 4px}}
  .score-bar{{height:16px;border-radius:8px;background:#1e1e3a;overflow:hidden}}
  .score-fill{{height:100%;background:{score_color};border-radius:8px;width:{score*10}%;transition:width .8s}}
  .score-label{{font-size:28px;font-weight:700;color:{score_color}}}
  @media(max-width:700px){{.charts{{grid-template-columns:1fr}}main{{padding:14px}}}}
  .hidden{{display:none}}
</style>
</head>
<body>
<header>
  <div>
    <h1>👁 OLHO DE DEUS</h1>
    <span>AI-Powered Pentest Dashboard</span>
  </div>
  <div class="meta">
    <div><b>Alvo:</b> {target}</div>
    <div><b>Data:</b> {now}</div>
    <div>Eduardo Felype</div>
  </div>
</header>
<main>

<!-- CARDS -->
<div class="cards">
  <div class="card score">
    <div class="num">{score}</div>
    <div class="lbl">Security Score</div>
    <div class="score-bar-wrap"><div class="score-bar"><div class="score-fill"></div></div></div>
    <div style="font-size:11px;color:{score_color};margin-top:4px">{score_label}</div>
  </div>
  <div class="card crit"><div class="num">{counts['CRITICAL']}</div><div class="lbl">Crítico</div></div>
  <div class="card high"><div class="num">{counts['HIGH']}</div><div class="lbl">Alto</div></div>
  <div class="card med"><div class="num">{counts['MEDIUM']}</div><div class="lbl">Médio</div></div>
  <div class="card low"><div class="num">{counts['LOW']}</div><div class="lbl">Baixo</div></div>
  <div class="card"><div class="num">{len(secrets)}</div><div class="lbl">Secrets</div></div>
  <div class="card"><div class="num">{len(techs)}</div><div class="lbl">Tecnologias</div></div>
</div>

<!-- CHARTS -->
<div class="charts">
  <div class="box">
    <h3>Distribuição de Severidade</h3>
    <canvas id="pieChart"></canvas>
  </div>
  <div class="box">
    <h3>Top Issues Recorrentes</h3>
    <canvas id="barChart"></canvas>
  </div>
</div>

<!-- AI INSIGHTS -->
{f'<div class="box insights"><h3>🤖 Insights da IA</h3><ul>{insight_items}</ul></div>' if insights else ''}

<!-- TOP ISSUES -->
{f'<div class="box"><h3>🔁 Memória Histórica da IA</h3>{top_items}</div>' if top_items else ''}

<!-- FINDINGS TABLE -->
<div class="box">
  <h3>Findings Priorizados</h3>
  <div class="filters">
    <button class="filter-btn active" onclick="filterFindings('ALL')">Todos</button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL')" style="color:#e63946">Crítico</button>
    <button class="filter-btn" onclick="filterFindings('HIGH')" style="color:#f4a261">Alto</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM')" style="color:#e9c46a">Médio</button>
    <button class="filter-btn" onclick="filterFindings('LOW')" style="color:#2a9d8f">Baixo</button>
  </div>
  <table>
    <thead><tr><th>Sev</th><th>Issue</th><th>URL</th><th>CVSS</th><th>Evidência</th><th>Fonte</th></tr></thead>
    <tbody id="findingsBody">{finding_rows}</tbody>
  </table>
</div>

<!-- SECRETS -->
{f'''<div class="box">
  <h3>🔑 Secrets e Credenciais Expostos</h3>
  <table>
    <thead><tr><th>Tipo</th><th>Valor</th><th>URL</th></tr></thead>
    <tbody>{secret_rows}</tbody>
  </table>
</div>''' if secrets else ''}

<!-- CVEs -->
{f'''<div class="box">
  <h3>⚠️ CVEs por Tecnologia Detectada</h3>
  <table>
    <thead><tr><th>CVE</th><th>Tecnologia</th><th>Severidade</th><th>Descrição</th></tr></thead>
    <tbody>{cve_rows}</tbody>
  </table>
</div>''' if cves else ''}

<!-- TECNOLOGIAS -->
{f'<div class="box"><h3>🧩 Stack Tecnológico</h3><div style="margin-top:8px">{tech_badges}</div></div>' if techs else ''}

</main>
<script>
// Pie chart
new Chart(document.getElementById('pieChart'), {{
  type:'doughnut',
  data:{{
    labels:['Critical','High','Medium','Low','Info'],
    datasets:[{{
      data:{pie_data},
      backgroundColor:['#e63946','#f4a261','#e9c46a','#2a9d8f','#457b9d'],
      borderWidth:2, borderColor:'#0d0d1a'
    }}]
  }},
  options:{{plugins:{{legend:{{labels:{{color:'#adb5bd',font:{{size:12}}}}}}}}}}
}});

// Bar chart
new Chart(document.getElementById('barChart'), {{
  type:'bar',
  data:{{
    labels:{top_labels},
    datasets:[{{
      label:'Ocorrências',
      data:{top_vals},
      backgroundColor:'#e63946cc',
      borderRadius:4
    }}]
  }},
  options:{{
    indexAxis:'y',
    plugins:{{legend:{{display:false}}}},
    scales:{{
      x:{{ticks:{{color:'#adb5bd'}},grid:{{color:'#1e1e3a'}}}},
      y:{{ticks:{{color:'#adb5bd',font:{{size:10}}}},grid:{{display:false}}}}
    }}
  }}
}});

// Filtro de findings
function filterFindings(sev) {{
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-row').forEach(row=>{{
    row.classList.toggle('hidden', sev!=='ALL' && row.dataset.sev!==sev);
  }});
}}
</script>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
