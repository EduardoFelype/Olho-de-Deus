"""
Evidence Engine — coleta e estrutura evidências de cada finding para o relatório.
"""
from core.utils import safe_request


def collect(url: str, response=None) -> dict:
    """Coleta evidência técnica de uma URL."""
    if response is None:
        response = safe_request(url)

    if not response:
        return {"url": url, "status": None, "size": 0, "preview": ""}

    return {
        "url":     url,
        "status":  response.status_code,
        "size":    len(response.text),
        "server":  response.headers.get("Server",""),
        "powered": response.headers.get("X-Powered-By",""),
        "preview": response.text[:200].replace("\n"," "),
    }


def enrich_finding(finding: dict) -> dict:
    """Adiciona evidência ao finding se ainda não tiver."""
    if finding.get("evidence"):
        return finding
    url = finding.get("url","")
    if url:
        finding["evidence"] = collect(url)
    return finding
