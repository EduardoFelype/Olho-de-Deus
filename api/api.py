"""
API REST — Olho de Deus v3
Expõe os resultados via FastAPI para integração com outros sistemas.
"""
import json, os, glob
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from config import Config

app = FastAPI(
    title="Olho de Deus API",
    description="AI-Powered Pentest Framework — Eduardo Felype",
    version="3.0"
)


class ScanRequest(BaseModel):
    target:     str
    pipeline:   str = "all"
    shodan_key: str = ""
    vt_key:     str = ""


@app.get("/")
def root():
    return {"name": "Olho de Deus", "version": "3.0", "status": "online"}


@app.get("/reports")
def list_reports():
    files = glob.glob(f"{Config.REPORT_DIR}/*.json")
    return {"reports": [os.path.basename(f) for f in files]}


@app.get("/reports/{filename}")
def get_report(filename: str):
    path = os.path.join(Config.REPORT_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Relatório não encontrado.")
    with open(path) as f:
        return json.load(f)


@app.get("/dashboard/{filename}", response_class=HTMLResponse)
def get_dashboard(filename: str):
    path = os.path.join(Config.REPORT_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Dashboard não encontrado.")
    with open(path, encoding="utf-8") as f:
        return f.read()


@app.get("/ai-memory")
def ai_memory():
    if not os.path.exists(Config.AI_MEMORY):
        return {}
    with open(Config.AI_MEMORY) as f:
        return json.load(f)


@app.post("/scan")
def start_scan(req: ScanRequest, bg: BackgroundTasks):
    def _run():
        import subprocess
        cmd = ["python", "main.py", req.target, "--pipeline", req.pipeline]
        if req.shodan_key:
            cmd += ["--shodan", req.shodan_key]
        if req.vt_key:
            cmd += ["--vt", req.vt_key]
        subprocess.run(cmd)
    bg.add_task(_run)
    return {"status": "started", "target": req.target, "pipeline": req.pipeline}
