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
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

C_RED    = colors.HexColor("#e63946")
C_ORANGE = colors.HexColor("#f4a261")
C_YELLOW = colors.HexColor("#e9c46a")
C_GREEN  = colors.HexColor("#2a9d8f")
C_BLUE   = colors.HexColor("#457b9d")
C_DARK   = colors.HexColor("#1a1a2e")
C_LIGHT  = colors.HexColor("#f8f9fa")
C_GRAY   = colors.HexColor("#6c757d")
C_WHITE  = colors.white

SEV_COLORS = {
    "CRITICAL": C_RED,
    "HIGH":     C_ORANGE,
    "MEDIUM":   C_YELLOW,
    "LOW":      C_GREEN,
    "INFO":     C_BLUE,
}

CVSS_MAP = {
    "sqli error-based": 9.8, "sqli": 9.8, "sqli (http 500)": 7.5,
    "sqli blind": 8.1, "sqli blind boolean": 8.1,
    "xss refletido": 6.1, "xss em form": 6.1, "xss": 6.1,
    "possível ssrf": 8.6, "ssrf": 8.6,
    "path traversal": 7.5, "path sensível": 7.5,
    "secret exposto": 9.0, "cors": 6.5, "open redirect": 6.1,
    "idor": 7.5, "verb tampering": 6.5, "clickjacking": 4.3,
    "rate limit": 5.3,
    "critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5,
}

IMPACT_MAP = {
    "sqli":      "Acesso completo ao banco. Possível escalada para RCE.",
    "xss":       "Roubo de sessão, defacement, phishing direcionado.",
    "ssrf":      "Acesso a serviços internos e metadata de cloud.",
    "secret":    "Comprometimento de APIs, infraestrutura e autenticação.",
    "traversal": "Leitura de arquivos arbitrários no servidor.",
    "cors":      "Leitura cross-origin de dados autenticados.",
    "redirect":  "Phishing e bypass de controles de acesso.",
    "idor":      "Acesso não autorizado a recursos de outros usuários.",
    "verb":      "Execução de operações destrutivas sem autorização.",
    "click":     "Redirecionamento de cliques para ações maliciosas.",
    "default":   "Avaliar impacto conforme contexto da aplicação.",
}

REC_MAP = {
    "sqli":      "Usar prepared statements. Nunca concatenar inputs em queries.",
    "xss":       "Sanitizar outputs com htmlspecialchars. Implementar CSP restritiva.",
    "ssrf":      "Whitelist de URLs permitidas. Bloquear ranges privados no firewall.",
    "secret":    "Remover do código. Usar variáveis de ambiente e secret managers.",
    "traversal": "Validar e sanitizar caminhos. Usar chroot/jail quando possível.",
    "cors":      "Restringir Access-Control-Allow-Origin a origens confiáveis.",
    "redirect":  "Validar destinos de redirecionamento contra whitelist.",
    "idor":      "Implementar verificação de autorização em todos os recursos.",
    "verb":      "Restringir verbos HTTP desnecessários no servidor/WAF.",
    "click":     "Adicionar header X-Frame-Options: DENY ou CSP frame-ancestors.",
    "default":   "Revisar e corrigir conforme contexto da aplicação.",
}


# ── helpers ───────────────────────────────────────────────────────────────────

def _ps(size=9, color=colors.black, bold=False, align=TA_LEFT):
    """Cria ParagraphStyle com wrapping correto."""
    return ParagraphStyle(
        "s",
        fontSize=size,
        textColor=color,
        alignment=align,
        fontName="Helvetica-Bold" if bold else "Helvetica",
        leading=size * 1.4,        # espaçamento entre linhas = correção principal do PDF
        wordWrap="LTR",
        spaceAfter=2,
    )

def _psc(size=9, color=colors.black, bold=False):
    return _ps(size, color, bold, TA_CENTER)

def _badge_text(sev):
    c = {"CRITICAL": "#e63946", "HIGH": "#f4a261", "MEDIUM": "#e9c46a",
         "LOW": "#2a9d8f", "INFO": "#457b9d"}
    return f'<font color="{c.get(sev.upper(), "#999")}"><b>[{sev.upper()}]</b></font>'

def _score(report):
    """
    Score 0.0 a 10.0 — baseado em proporção ponderada de severidades.
    Lógica: quanto maior a proporção de findings graves no total, menor o score.
    Escala real:
      9-10  → site limpo ou só LOW
      7-8.9 → alguns MEDIUMs
      5-6.9 → HIGHs presentes
      3-4.9 → CRITICALs presentes mas poucos
      1-2.9 → muitos CRITICALs
      0-0.9 → site completamente comprometido
    """
    findings = (report.get("findings_prioritized") or
                report.get("findings") or [])

    if not findings:
        return 10.0

    # Peso de cada severidade (0 a 1, quanto prejudica o score)
    SEV_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.6, "MEDIUM": 0.25, "LOW": 0.05}

    total   = len(findings)
    w_sum   = 0.0
    w_max   = 0.0  # maximo possivel se todos fossem CRITICAL

    for f in findings:
        sev    = (f.get("severity") or "").upper()
        weight = SEV_WEIGHT.get(sev, 0.1)
        w_sum += weight
        w_max += SEV_WEIGHT["CRITICAL"]

    # ratio: 0.0 = tudo LOW, 1.0 = tudo CRITICAL
    ratio = w_sum / w_max if w_max else 0

    # Volume modifier: poucos findings pesam menos mesmo sendo graves
    # 1 finding CRITICAL = score 5, nao 0
    import math
    volume_factor = min(math.log(total + 1) / math.log(20), 1.0)

    # Score base: ratio * volume_factor define o quanto penaliza
    effective_ratio = ratio * volume_factor
    score = round((1.0 - effective_ratio) * 10, 1)

    # Penalidade extra por secrets (reduz ate 1.5 pontos)
    secrets = report.get("secrets") or []
    if secrets:
        score = round(max(score - min(len(secrets) * 0.3, 1.5), 0), 1)

    # Penalidade por CVEs criticos (reduz ate 1.0 ponto)
    cve_penalty = 0.0
    for cv in (report.get("cve_matches") or []):
        if (cv.get("severity") or "").upper() == "CRITICAL":
            cve_penalty += 0.15
    score = round(max(score - min(cve_penalty, 1.0), 0), 1)

    return score

def _counts(report):
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in report.get("findings_prioritized", []):
        k = f.get("severity", "INFO").upper()
        c[k] = c.get(k, 0) + 1
    for _ in report.get("secrets", []):
        c["CRITICAL"] += 1
    return c

def _get_cvss(f):
    text = (f.get("issue", "") + " " + f.get("type", "")).lower()
    for k, v in CVSS_MAP.items():
        if k in text:
            return v
    return CVSS_MAP.get(f.get("severity", "low").lower(), 5.0)

def _get_impact(f):
    text = (f.get("issue", "") + " " + f.get("type", "")).lower()
    for k, v in IMPACT_MAP.items():
        if k in text:
            return v
    return IMPACT_MAP["default"]

def _get_rec(f):
    text = (f.get("issue", "") + " " + f.get("type", "")).lower()
    for k, v in REC_MAP.items():
        if k in text:
            return v
    return REC_MAP["default"]

def _trunc(s, n):
    s = str(s or "")
    return s[:n] + "…" if len(s) > n else s

def _pie(counts):
    labels = [k for k in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] if counts[k] > 0]
    vals   = [counts[k] for k in labels]
    if not vals:
        d = Drawing(400, 160)
        d.add(String(200, 80, "Sem findings", textAnchor="middle",
                     fontSize=10, fillColor=C_GRAY))
        return d
    # Drawing largo o suficiente para labels nao cortarem
    d   = Drawing(460, 220)
    pie = Pie()
    # pie centralizado com espaco para labels dos dois lados
    pie.x = 130; pie.y = 30
    pie.width = 160; pie.height = 160
    pie.data   = vals
    pie.labels = [f"{l} ({v})" for l, v in zip(labels, vals)]
    pie.sideLabels       = True
    pie.sideLabelsOffset = 0.15
    pie.simpleLabels     = False
    pie.slices.strokeWidth  = 0.8
    pie.slices.strokeColor  = colors.white
    for i, l in enumerate(labels):
        pie.slices[i].fillColor = SEV_COLORS.get(l, C_BLUE)
    d.add(pie)
    return d

def _scorebar(score):
    fill = C_RED if score < 4 else (C_ORANGE if score < 7 else C_GREEN)
    d = Drawing(420, 50)
    # trilha cinza
    d.add(Rect(0, 12, 360, 26, fillColor=colors.HexColor("#dddddd"), strokeColor=None))
    # barra colorida proporcional
    bar_w = max(int(360 * score / 10), 4) if score > 0 else 0
    if bar_w:
        d.add(Rect(0, 12, bar_w, 26, fillColor=fill, strokeColor=None))
    # texto do score ao lado direito
    d.add(String(368, 18, f"{score}/10", fontSize=14,
                 fontName="Helvetica-Bold", fillColor=fill))
    return d


# ── PDF principal ─────────────────────────────────────────────────────────────

def generate_pdf(report, filename="report.pdf"):
    PAGE_W = 21 * cm
    doc = SimpleDocTemplate(
        filename,
        pagesize=(PAGE_W, 29.7 * cm),
        rightMargin=1.8 * cm, leftMargin=1.8 * cm,
        topMargin=1.5 * cm,   bottomMargin=1.5 * cm,
    )
    # largura útil da tabela
    TW = PAGE_W - 3.6 * cm

    now    = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    target = report.get("target", "N/A")
    score  = _score(report)
    counts = _counts(report)
    total  = sum(counts.values())
    C = []

    # ── CAPA ─────────────────────────────────────────────────────────────────
    C.append(Spacer(1, 1 * cm))
    C.append(Paragraph("OLHO DE DEUS", _psc(28, C_RED, bold=True)))
    C.append(Spacer(1, 0.2 * cm))
    C.append(Paragraph("Relatório Técnico de Segurança — AI-Powered Pentest",
                        _psc(11, C_GRAY)))
    C.append(HRFlowable(width="100%", thickness=2, color=C_RED, spaceAfter=10))
    C.append(Spacer(1, 0.3 * cm))

    info_rows = [
        ["Alvo",          target],
        ["Data",          now],
        ["Total Findings", str(total)],
    ]
    t = Table(info_rows, colWidths=[4 * cm, TW - 4 * cm])
    t.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",  (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",  (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), C_DARK),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.3, C_GRAY),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_LIGHT]),
    ]))
    C.append(t)
    C.append(Spacer(1, 0.5 * cm))

    C.append(Paragraph("Security Score", _ps(13, C_RED, bold=True)))
    C.append(Spacer(1, 0.2 * cm))
    C.append(renderPDF.GraphicsFlowable(_scorebar(score)))
    lbl_color = C_RED if score < 4 else (C_ORANGE if score < 7 else C_GREEN)
    lbl_text  = ("CRÍTICO — Ação imediata" if score < 4
                 else "ATENÇÃO — Vulnerabilidades significativas" if score < 7
                 else "BOM — Poucos problemas")
    C.append(Paragraph(lbl_text, _ps(9, lbl_color)))
    C.append(Spacer(1, 0.6 * cm))

    # ── RESUMO EXECUTIVO ─────────────────────────────────────────────────────
    C.append(Paragraph("Resumo Executivo", _ps(14, C_RED, bold=True)))
    C.append(Spacer(1, 0.2 * cm))

    sev_rows = [["Severidade", "Qtd", "Prazo recomendado"]]
    prazo_map = {"CRITICAL": "Imediato (< 24h)", "HIGH": "≤ 7 dias",
                 "MEDIUM": "≤ 30 dias", "LOW": "Próximo ciclo"}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev] > 0:
            sev_rows.append([
                Paragraph(_badge_text(sev), _ps(9)),
                str(counts[sev]),
                prazo_map[sev],
            ])
    if len(sev_rows) > 1:
        t = Table(sev_rows, colWidths=[5 * cm, 2.5 * cm, TW - 7.5 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("GRID",        (0, 0), (-1, -1), 0.4, C_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LIGHT]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ]))
        C.append(t)

    C.append(Spacer(1, 0.5 * cm))
    C.append(Paragraph("Distribuição por Severidade", _ps(12, C_RED, bold=True)))
    C.append(renderPDF.GraphicsFlowable(_pie(counts)))
    C.append(PageBreak())

    # ── AI INSIGHTS ──────────────────────────────────────────────────────────
    insights = report.get("ai_insights", [])
    if insights:
        C.append(Paragraph("Insights da IA", _ps(14, C_RED, bold=True)))
        C.append(Spacer(1, 0.2 * cm))
        for ins in insights:
            C.append(Paragraph(f"  {ins}", _ps(9)))
        C.append(Spacer(1, 0.5 * cm))

    # ── TOP ISSUES HISTÓRICOS ─────────────────────────────────────────────────
    top = report.get("ai_top_issues", [])
    if top:
        C.append(Paragraph("Issues mais recorrentes (memória histórica)",
                            _ps(12, C_RED, bold=True)))
        C.append(Spacer(1, 0.2 * cm))
        rows = [["Issue", "Ocorrências"]]
        for item in top[:8]:
            rows.append([
                Paragraph(_trunc(item.get("issue", ""), 80), _ps(9)),
                str(item.get("count", 0)),
            ])
        t = Table(rows, colWidths=[TW - 3 * cm, 3 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("GRID",        (0, 0), (-1, -1), 0.4, C_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LIGHT]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ]))
        C.append(t)
        C.append(Spacer(1, 0.5 * cm))

    # ── FINDINGS CRÍTICOS E ALTOS ─────────────────────────────────────────────
    prioritized = report.get("findings_prioritized", [])
    crit_high   = [f for f in prioritized
                   if f.get("severity", "").upper() in ("CRITICAL", "HIGH")]
    if crit_high:
        C.append(Paragraph("Vulnerabilidades Críticas e Altas",
                            _ps(14, C_RED, bold=True)))
        C.append(Spacer(1, 0.2 * cm))
        for i, f in enumerate(crit_high[:25], 1):
            sev   = f.get("severity", "INFO").upper()
            issue = _trunc(f.get("issue") or f.get("type", "Desconhecido"), 80)
            url   = _trunc(f.get("url", target), 90)
            cvss  = _get_cvss(f)
            ev    = _trunc(
                f.get("evidence", "") or f.get("payload", "") or f.get("value", ""), 100)

            block = [
                Paragraph(f"{i}. {_badge_text(sev)}  {issue}",
                           _ps(10, bold=True)),
                Paragraph(f"<b>URL:</b> {url}", _ps(8)),
                Paragraph(f"<b>CVSS estimado:</b> {cvss}", _ps(8)),
                Paragraph(f"<b>Impacto:</b> {_get_impact(f)}", _ps(8)),
                Paragraph(f"<b>Recomendação:</b> {_get_rec(f)}", _ps(8)),
            ]
            if ev:
                block.append(
                    Paragraph(f"<b>Evidência:</b> {ev}",
                              _ps(8, colors.HexColor("#2d6a4f"))))
            block.append(HRFlowable(width="100%", thickness=0.4,
                                    color=C_GRAY, spaceAfter=6))
            C.append(KeepTogether(block))
            C.append(Spacer(1, 0.1 * cm))

    C.append(PageBreak())

    # ── SECRETS ──────────────────────────────────────────────────────────────
    secrets = report.get("secrets", [])
    if secrets:
        C.append(Paragraph("Secrets e Credenciais Expostos",
                            _ps(14, C_RED, bold=True)))
        C.append(Spacer(1, 0.2 * cm))
        rows = [["Tipo", "Valor (truncado)", "URL"]]
        for s in secrets[:30]:
            rows.append([
                Paragraph(s.get("type", ""), _ps(8)),
                Paragraph(_trunc(s.get("value", ""), 35), _ps(8)),
                Paragraph(_trunc(s.get("url", ""), 50), _ps(8)),
            ])
        cw = [4 * cm, 5 * cm, TW - 9 * cm]
        t  = Table(rows, colWidths=cw)
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), C_RED),
            ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("GRID",        (0, 0), (-1, -1), 0.4, C_GRAY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#fff5f5"), C_WHITE]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        C.append(t)
        C.append(Spacer(1, 0.5 * cm))

    # ── TECNOLOGIAS + CVEs ────────────────────────────────────────────────────
    techs = report.get("technologies", [])
    cves  = report.get("cve_matches", [])
    if techs:
        C.append(Paragraph("Stack Tecnológico e CVEs", _ps(14, C_RED, bold=True)))
        C.append(Spacer(1, 0.2 * cm))
        C.append(Paragraph("  •  ".join(techs), _ps(9)))
        if cves:
            C.append(Spacer(1, 0.3 * cm))
            rows = [["CVE", "Tech", "Sev.", "Descrição"]]
            for cv in cves[:20]:
                rows.append([
                    Paragraph(cv.get("cve", ""), _ps(8)),
                    Paragraph(cv.get("tech", ""), _ps(8)),
                    Paragraph(_badge_text(cv.get("severity", "")), _ps(8)),
                    Paragraph(_trunc(cv.get("desc", ""), 60), _ps(8)),
                ])
            cw = [3 * cm, 2.5 * cm, 2.5 * cm, TW - 8 * cm]
            t  = Table(rows, colWidths=cw)
            t.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (-1, 0), C_DARK),
                ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
                ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",    (0, 0), (-1, -1), 8),
                ("GRID",        (0, 0), (-1, -1), 0.4, C_GRAY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LIGHT]),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))
            C.append(t)
        C.append(Spacer(1, 0.5 * cm))

    # ── RECOMENDAÇÕES GERAIS ─────────────────────────────────────────────────
    C.append(Paragraph("Recomendações Gerais", _ps(14, C_RED, bold=True)))
    C.append(Spacer(1, 0.2 * cm))
    recs = [
        "Implementar WAF na frente da aplicação.",
        "Habilitar todos os security headers (CSP, HSTS, X-Frame-Options, etc.).",
        "Remover secrets do frontend. Usar variáveis de ambiente e secret managers.",
        "Adotar prepared statements em todas as queries SQL.",
        "Implementar rate limiting em endpoints de autenticação.",
        "Manter dependências atualizadas com patches de segurança.",
        "Configurar monitoramento de logs com alertas para padrões de ataque.",
        "Realizar pentest manual focado nos findings críticos deste relatório.",
    ]
    for rec in recs:
        C.append(Paragraph(f"  ▸  {rec}", _ps(9)))

    C.append(Spacer(1, 1 * cm))
    C.append(HRFlowable(width="100%", thickness=1, color=C_RED))
    C.append(Spacer(1, 0.3 * cm))
    C.append(Paragraph(
        f"Gerado por <b>Olho de Deus v3</b> — Eduardo Felype | {now}",
        _psc(8, C_GRAY),
    ))
    doc.build(C)


# ─── HTML DASHBOARD ──────────────────────────────────────────────────────────

def generate_dashboard(report, filename="dashboard.html"):
    now    = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    target = report.get("target", "N/A")
    score  = _score(report)
    counts = _counts(report)

    # garante score minimo real quando ha findings
    total_f = sum(counts.values())
    if total_f > 0 and score == 10.0:
        score = round(max(10.0 - total_f * 0.2, 0), 1)

    findings  = report.get("findings_prioritized") or []
    secrets   = report.get("secrets") or []
    techs     = report.get("technologies") or []
    insights  = report.get("ai_insights") or []
    top_issues= report.get("ai_top_issues") or []
    cves      = report.get("cve_matches") or []
    waf       = report.get("waf", {})
    subdoms   = report.get("subdomains") or []
    ssl_info  = report.get("ssl", {})
    graphql   = report.get("graphql", {})
    api_fuzz  = report.get("api_fuzzer", {})
    exploit   = report.get("exploitation") or []
    passive   = report.get("passive", {})

    score_color = "#e63946" if score < 4 else ("#f4a261" if score < 7 else "#2a9d8f")
    score_label = "CRÍTICO" if score < 4 else ("ATENÇÃO" if score < 7 else "BOM")
    score_pct   = int(score * 10)

    SEV_HEX = {
        "CRITICAL": "#e63946", "HIGH": "#f4a261",
        "MEDIUM":   "#e9c46a", "LOW":  "#2a9d8f", "INFO": "#457b9d",
    }

    def badge(sev):
        c = SEV_HEX.get(sev.upper(), "#666")
        return f'<span class="badge" style="background:{c}">{sev}</span>'

    # ── findings table rows ──────────────────────────────────────────────────
    finding_rows = ""
    for f in findings[:80]:
        sev   = f.get("severity", "INFO").upper()
        issue = f.get("issue") or f.get("type", "")
        url   = f.get("url", "")
        ev    = str(f.get("evidence", "") or f.get("payload", "") or
                    f.get("value", ""))[:100]
        src   = f.get("source", "")
        cvss  = _get_cvss(f)
        rec   = _get_rec(f)
        imp   = _get_impact(f)
        finding_rows += f"""
        <tr class="finding-row" data-sev="{sev}">
          <td>{badge(sev)}</td>
          <td>
            <div class="issue-title">{issue}</div>
            <div class="issue-detail">{imp}</div>
          </td>
          <td><a href="{url}" target="_blank" class="url-link">{url[:70]}</a></td>
          <td class="cvss-cell">{cvss}</td>
          <td class="ev">{ev}</td>
          <td>
            <span class="source">{src}</span>
            <div class="rec">{rec}</div>
          </td>
        </tr>"""

    # ── secrets rows ─────────────────────────────────────────────────────────
    secret_rows = ""
    for s in secrets[:30]:
        secret_rows += f"""
        <tr>
          <td>{badge("CRITICAL")}<br><small>{s.get("type","")}</small></td>
          <td class="ev">{str(s.get("value",""))[:80]}</td>
          <td><a href="{s.get("url","")}" target="_blank">{s.get("url","")[:70]}</a></td>
        </tr>"""

    # ── CVE rows ──────────────────────────────────────────────────────────────
    cve_rows = ""
    for cv in cves[:25]:
        sc = SEV_HEX.get(cv.get("severity", ""), "#adb5bd")
        cve_rows += f"""
        <tr>
          <td><a href="https://nvd.nist.gov/vuln/detail/{cv.get('cve','')}"
               target="_blank" class="cve-link">{cv.get("cve","")}</a></td>
          <td>{cv.get("tech","")}</td>
          <td><span class="badge" style="background:{sc}">{cv.get("severity","")}</span></td>
          <td>{cv.get("desc","")}</td>
        </tr>"""

    # ── subdomains ────────────────────────────────────────────────────────────
    subdom_items = ""
    for s in (subdoms if isinstance(subdoms, list) else [])[:20]:
        subdom_items += f'<span class="tech-badge">{s}</span>'

    # ── tech badges ───────────────────────────────────────────────────────────
    tech_badges = "".join(f'<span class="tech-badge">{t}</span>' for t in techs)

    # ── WAF info ──────────────────────────────────────────────────────────────
    waf_html = ""
    if isinstance(waf, dict) and waf.get("detected"):
        hints = "".join(f"<li>{h}</li>" for h in waf.get("bypass_hints", []))
        waf_html = f"""
        <div class="box">
          <h3>🛡️ WAF Detectado</h3>
          <div class="waf-info">
            <span class="waf-name">{waf.get("waf","")}</span>
            <span class="confidence">Confiança: {waf.get("confidence",0)}%</span>
          </div>
          {"<div class='bypass-hints'><b>Bypass hints:</b><ul>" + hints + "</ul></div>" if hints else ""}
        </div>"""

    # ── SSL info ──────────────────────────────────────────────────────────────
    ssl_html = ""
    if isinstance(ssl_info, dict) and ssl_info:
        ssl_issues = ssl_info.get("issues", [])
        ssl_grade  = ssl_info.get("grade", "N/A")
        ssl_items  = "".join(f"<li>{i}</li>" for i in ssl_issues[:10])
        ssl_html = f"""
        <div class="box">
          <h3>🔒 SSL/TLS</h3>
          <div>Grade: <b style="color:{score_color}">{ssl_grade}</b></div>
          {("<ul class='ssl-issues'>" + ssl_items + "</ul>") if ssl_items else "<p style='color:#2a9d8f'>Nenhum problema SSL detectado.</p>"}
        </div>"""

    # ── API fuzzer ────────────────────────────────────────────────────────────
    api_html = ""
    if isinstance(api_fuzz, dict):
        exposed = api_fuzz.get("exposed_endpoints", [])
        verbs   = api_fuzz.get("verb_tampering", [])
        if exposed or verbs:
            exp_rows = "".join(
                f'<tr><td><a href="{e.get("url","")}" target="_blank">{e.get("url","")}</a></td>'
                f'<td>{e.get("status","")}</td><td>{e.get("issue","Exposto")}</td></tr>'
                for e in (exposed + verbs)[:15]
            )
            api_html = f"""
            <div class="box">
              <h3>🔌 API Fuzzer</h3>
              <table>
                <thead><tr><th>Endpoint</th><th>Status</th><th>Issue</th></tr></thead>
                <tbody>{exp_rows}</tbody>
              </table>
            </div>"""

    # ── insights ──────────────────────────────────────────────────────────────
    insight_items = "".join(f"<li>{i}</li>" for i in insights)

    # ── top issues ────────────────────────────────────────────────────────────
    top_items = "".join(
        f"<div class='top-item'><span>{i.get('issue','')}</span>"
        f"<b class='top-count'>{i.get('count',0)}x</b></div>"
        for i in top_issues
    )

    # Chart.js data
    pie_data   = json.dumps([counts[k] for k in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]])
    top_labels = json.dumps([str(i.get("issue",""))[:30] for i in top_issues[:8]])
    top_vals   = json.dumps([i.get("count",0) for i in top_issues[:8]])

    # ── Passive info card ─────────────────────────────────────────────────────
    whois_org = ""
    if isinstance(passive, dict):
        w = passive.get("whois", {})
        if isinstance(w, dict):
            whois_org = w.get("org", "") or w.get("registrant", "") or ""

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
    --green:#2a9d8f; --blue:#457b9d; --gray:#adb5bd;
    --white:#f1faee; --dim:#8892a4;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--white);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.5}}

  /* HEADER */
  header{{background:var(--panel);border-bottom:2px solid var(--red);padding:16px 28px;
          display:flex;align-items:center;gap:20px;position:sticky;top:0;z-index:100}}
  .header-logo{{font-size:22px;font-weight:800;color:var(--red);letter-spacing:3px}}
  .header-sub{{color:var(--dim);font-size:12px;margin-top:2px}}
  .header-meta{{margin-left:auto;text-align:right;font-size:12px;color:var(--dim);line-height:1.8}}
  .header-meta b{{color:var(--white)}}

  /* LAYOUT */
  main{{padding:24px 28px;display:flex;flex-direction:column;gap:20px;max-width:1400px;margin:0 auto}}

  /* CARDS */
  .cards{{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:12px}}
  .card{{background:var(--panel);border:1px solid var(--border);border-radius:10px;
         padding:16px 12px;text-align:center;transition:.2s}}
  .card:hover{{border-color:var(--red);transform:translateY(-2px)}}
  .card .num{{font-size:32px;font-weight:800;line-height:1.1}}
  .card .lbl{{font-size:10px;color:var(--dim);margin-top:4px;text-transform:uppercase;letter-spacing:.8px}}
  .card.crit{{border-color:rgba(230,57,70,.4)}} .card.crit .num{{color:var(--red)}}
  .card.high{{border-color:rgba(244,162,97,.4)}} .card.high .num{{color:var(--orange)}}
  .card.med {{border-color:rgba(233,196,106,.4)}} .card.med  .num{{color:var(--yellow)}}
  .card.low {{border-color:rgba(42,157,143,.4)}}  .card.low  .num{{color:var(--green)}}
  .card.info-c .num{{color:var(--blue)}}

  /* SCORE */
  .score-num{{font-size:36px;font-weight:800;color:{score_color}}}
  .score-label{{font-size:11px;color:{score_color};margin-top:2px;font-weight:600}}
  .score-bar-track{{height:8px;background:#1e1e3a;border-radius:4px;margin:8px 0;overflow:hidden}}
  .score-bar-fill{{height:100%;border-radius:4px;background:{score_color};
                   width:{score_pct}%;transition:width 1s ease}}

  /* BOX */
  .box{{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:20px}}
  .box h3{{font-size:12px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;
           color:var(--red);margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}}

  /* CHARTS ROW */
  .charts{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
  canvas{{max-height:260px}}

  /* FILTERS */
  .filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center}}
  .filter-btn{{background:transparent;border:1px solid var(--border);color:var(--dim);
               padding:5px 14px;border-radius:20px;cursor:pointer;font-size:12px;
               transition:.15s;font-family:inherit}}
  .filter-btn:hover,.filter-btn.active{{border-color:var(--red);color:var(--white);background:#1a0d10}}
  .filter-count{{font-size:11px;color:var(--dim);margin-left:auto}}

  /* TABLE */
  .table-wrap{{overflow-x:auto}}
  table{{width:100%;border-collapse:collapse;font-size:12px;min-width:700px}}
  th{{background:#0d0d1a;color:var(--dim);padding:9px 10px;text-align:left;
      font-size:10px;letter-spacing:.8px;text-transform:uppercase;
      border-bottom:1px solid var(--border);white-space:nowrap}}
  td{{padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:top;max-width:280px}}
  tr.finding-row:hover td{{background:#14142a}}
  .issue-title{{font-weight:600;color:var(--white);margin-bottom:2px}}
  .issue-detail{{font-size:11px;color:var(--dim);line-height:1.4}}
  .rec{{font-size:10px;color:var(--green);margin-top:4px;line-height:1.4}}

  /* MISC */
  .badge{{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;
          font-weight:700;color:#fff;white-space:nowrap}}
  .source{{font-size:10px;color:var(--dim);background:#0d0d1a;padding:2px 6px;
           border-radius:3px;white-space:nowrap}}
  .ev{{font-family:'Cascadia Code','Consolas',monospace;font-size:10px;
       color:#7ec8a0;word-break:break-all;max-width:200px}}
  .cvss-cell{{font-weight:700;text-align:center;white-space:nowrap}}
  a,.url-link{{color:var(--blue);text-decoration:none;word-break:break-all}}
  a:hover,.url-link:hover{{text-decoration:underline;color:var(--white)}}
  .cve-link{{color:var(--orange)}}
  .tech-badge{{background:#1a1a2e;border:1px solid var(--border);padding:4px 10px;
               border-radius:12px;font-size:11px;margin:3px;display:inline-block}}
  .top-item{{display:flex;justify-content:space-between;align-items:center;
             padding:9px 12px;background:#0d0d1a;border-radius:6px;
             margin-bottom:6px;font-size:12px;border:1px solid var(--border)}}
  .top-count{{color:var(--red);font-size:14px;font-weight:800}}
  .hidden{{display:none!important}}
  .waf-info{{display:flex;align-items:center;gap:12px;margin-bottom:10px}}
  .waf-name{{font-size:16px;font-weight:700;color:var(--orange)}}
  .confidence{{font-size:12px;color:var(--dim)}}
  .bypass-hints ul{{margin-left:16px;font-size:12px;color:var(--dim);margin-top:6px}}
  .ssl-issues{{margin-left:16px;font-size:12px;color:var(--orange);margin-top:8px}}
  .insights-list{{list-style:none;display:flex;flex-direction:column;gap:8px}}
  .insights-list li{{background:#0d0d1a;border-left:3px solid var(--red);
                     padding:10px 14px;border-radius:0 6px 6px 0;font-size:13px}}
  .empty{{color:var(--dim);font-size:13px;padding:12px 0;text-align:center}}
  @media(max-width:768px){{
    .charts{{grid-template-columns:1fr}}
    main{{padding:14px}}
    header{{flex-wrap:wrap}}
    .header-meta{{margin-left:0;text-align:left}}
  }}
</style>
</head>
<body>

<header>
  <div>
    <div class="header-logo">👁 OLHO DE DEUS</div>
    <div class="header-sub">AI-Powered Pentest Dashboard v3</div>
  </div>
  <div class="header-meta">
    <div><b>Alvo:</b> {target}</div>
    <div><b>Data:</b> {now}</div>
    {f'<div><b>Org:</b> {whois_org}</div>' if whois_org else ''}
  </div>
</header>

<main>

<!-- ── CARDS ─────────────────────────────────────────────────────────── -->
<div class="cards">
  <div class="card score">
    <div class="score-num">{score}</div>
    <div class="score-bar-track"><div class="score-bar-fill"></div></div>
    <div class="score-label">{score_label}</div>
    <div class="lbl">Security Score</div>
  </div>
  <div class="card crit">
    <div class="num">{counts['CRITICAL']}</div>
    <div class="lbl">Crítico</div>
  </div>
  <div class="card high">
    <div class="num">{counts['HIGH']}</div>
    <div class="lbl">Alto</div>
  </div>
  <div class="card med">
    <div class="num">{counts['MEDIUM']}</div>
    <div class="lbl">Médio</div>
  </div>
  <div class="card low">
    <div class="num">{counts['LOW']}</div>
    <div class="lbl">Baixo</div>
  </div>
  <div class="card info-c">
    <div class="num">{len(secrets)}</div>
    <div class="lbl">Secrets</div>
  </div>
  <div class="card">
    <div class="num">{len(techs)}</div>
    <div class="lbl">Tecnologias</div>
  </div>
  <div class="card">
    <div class="num">{len(cves)}</div>
    <div class="lbl">CVEs</div>
  </div>
  <div class="card">
    <div class="num">{len(exploit)}</div>
    <div class="lbl">Exploits</div>
  </div>
  {f'<div class="card"><div class="num">{len(subdoms)}</div><div class="lbl">Subdomínios</div></div>' if subdoms else ''}
</div>

<!-- ── CHARTS ─────────────────────────────────────────────────────────── -->
<div class="charts">
  <div class="box">
    <h3>Distribuição de Severidade</h3>
    <canvas id="pieChart"></canvas>
  </div>
  <div class="box">
    <h3>Top Issues Recorrentes</h3>
    {'<canvas id="barChart"></canvas>' if top_issues else '<p class="empty">Sem dados históricos ainda.</p>'}
  </div>
</div>

<!-- ── AI INSIGHTS ────────────────────────────────────────────────────── -->
{f'<div class="box"><h3>🤖 Insights da IA</h3><ul class="insights-list">{insight_items}</ul></div>' if insights else ''}

<!-- ── TOP ISSUES ─────────────────────────────────────────────────────── -->
{f'<div class="box"><h3>🔁 Memória Histórica da IA</h3>{top_items}</div>' if top_items else ''}

<!-- ── WAF ────────────────────────────────────────────────────────────── -->
{waf_html}

<!-- ── SSL ────────────────────────────────────────────────────────────── -->
{ssl_html}

<!-- ── FINDINGS TABLE ─────────────────────────────────────────────────── -->
<div class="box">
  <h3>Findings Priorizados</h3>
  <div class="filters">
    <button class="filter-btn active" onclick="filterFindings('ALL',this)">
      Todos <small>({len(findings)})</small>
    </button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL',this)"
            style="color:var(--red)">Crítico <small>({counts['CRITICAL']})</small></button>
    <button class="filter-btn" onclick="filterFindings('HIGH',this)"
            style="color:var(--orange)">Alto <small>({counts['HIGH']})</small></button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM',this)"
            style="color:var(--yellow)">Médio <small>({counts['MEDIUM']})</small></button>
    <button class="filter-btn" onclick="filterFindings('LOW',this)"
            style="color:var(--green)">Baixo <small>({counts['LOW']})</small></button>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Sev</th><th>Issue / Impacto</th><th>URL</th>
          <th>CVSS</th><th>Evidência</th><th>Fonte / Rec.</th>
        </tr>
      </thead>
      <tbody id="findingsBody">
        {finding_rows if finding_rows else '<tr><td colspan="6" class="empty">Nenhum finding encontrado.</td></tr>'}
      </tbody>
    </table>
  </div>
</div>

<!-- ── SECRETS ────────────────────────────────────────────────────────── -->
{f'''<div class="box">
  <h3>🔑 Secrets e Credenciais Expostos ({len(secrets)})</h3>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Tipo</th><th>Valor</th><th>URL</th></tr></thead>
      <tbody>{secret_rows}</tbody>
    </table>
  </div>
</div>''' if secrets else ''}

<!-- ── CVEs ───────────────────────────────────────────────────────────── -->
{f'''<div class="box">
  <h3>⚠️ CVEs por Tecnologia Detectada ({len(cves)})</h3>
  <div class="table-wrap">
    <table>
      <thead><tr><th>CVE</th><th>Tecnologia</th><th>Severidade</th><th>Descrição</th></tr></thead>
      <tbody>{cve_rows}</tbody>
    </table>
  </div>
</div>''' if cves else ''}

<!-- ── API FUZZER ─────────────────────────────────────────────────────── -->
{api_html}

<!-- ── TECNOLOGIAS ────────────────────────────────────────────────────── -->
{f'<div class="box"><h3>🧩 Stack Tecnológico</h3><div style="margin-top:8px">{tech_badges}</div></div>' if techs else ''}

<!-- ── SUBDOMÍNIOS ────────────────────────────────────────────────────── -->
{f'<div class="box"><h3>🌐 Subdomínios ({len(subdoms)})</h3><div style="margin-top:8px">{subdom_items}</div></div>' if subdoms else ''}

</main>

<script>
// ── Pie chart ───────────────────────────────────────────────────────────────
const pieCtx = document.getElementById('pieChart');
if (pieCtx) {{
  new Chart(pieCtx, {{
    type: 'doughnut',
    data: {{
      labels: ['Critical','High','Medium','Low','Info'],
      datasets: [{{
        data: {pie_data},
        backgroundColor: ['#e63946','#f4a261','#e9c46a','#2a9d8f','#457b9d'],
        borderWidth: 2,
        borderColor: '#12122a'
      }}]
    }},
    options: {{
      cutout: '55%',
      plugins: {{
        legend: {{
          position: 'right',
          labels: {{ color: '#adb5bd', font: {{ size: 12 }}, padding: 12 }}
        }}
      }}
    }}
  }});
}}

// ── Bar chart ───────────────────────────────────────────────────────────────
const barCtx = document.getElementById('barChart');
if (barCtx) {{
  new Chart(barCtx, {{
    type: 'bar',
    data: {{
      labels: {top_labels},
      datasets: [{{
        label: 'Ocorrências',
        data: {top_vals},
        backgroundColor: '#e6394688',
        borderColor: '#e63946',
        borderWidth: 1,
        borderRadius: 4
      }}]
    }},
    options: {{
      indexAxis: 'y',
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        x: {{ ticks: {{ color: '#adb5bd' }}, grid: {{ color: '#1e1e3a' }} }},
        y: {{ ticks: {{ color: '#adb5bd', font: {{ size: 11 }} }}, grid: {{ display: false }} }}
      }}
    }}
  }});
}}

// ── Filtro de findings ──────────────────────────────────────────────────────
function filterFindings(sev, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  let visible = 0;
  document.querySelectorAll('.finding-row').forEach(row => {{
    const show = sev === 'ALL' || row.dataset.sev === sev;
    row.classList.toggle('hidden', !show);
    if (show) visible++;
  }});
  const counter = document.querySelector('.filter-count');
  if (counter) counter.textContent = visible + ' findings';
}}
</script>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)