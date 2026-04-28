"""
Contexto compartilhado entre todos os módulos e pipelines.
Funciona como memória de trabalho da sessão atual.
"""
import sqlite3
import json
import threading
from config import Config

class SharedContext:
    def __init__(self):
        self._lock      = threading.Lock()
        self.target     = ""
        self.endpoints  = []
        self.findings   = []
        self.pages      = []          # páginas coletadas pelo crawler
        self._visited   = set()
        self._db        = None

    # ── URLs ──────────────────────────────────────────────────────────────────
    def add_url(self, url: str):
        with self._lock:
            if url not in self._visited:
                self._visited.add(url)
                self.endpoints.append(url)

    # ── Findings ──────────────────────────────────────────────────────────────
    def add_finding(self, finding: dict):
        with self._lock:
            finding.setdefault("severity", "INFO")
            self.findings.append(finding)
            self._persist_finding(finding)

    def all_findings(self):
        with self._lock:
            return list(self.findings)

    # ── Páginas ───────────────────────────────────────────────────────────────
    def add_pages(self, pages: list):
        with self._lock:
            self.pages.extend(pages)

    # ── Persistência SQLite ───────────────────────────────────────────────────
    def init_db(self):
        self._db = sqlite3.connect(Config.DB_PATH, check_same_thread=False)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                target   TEXT,
                severity TEXT,
                issue    TEXT,
                url      TEXT,
                evidence TEXT,
                ts       DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self._db.commit()

    def _persist_finding(self, f: dict):
        if not self._db:
            return
        try:
            self._db.execute(
                "INSERT INTO findings (target,severity,issue,url,evidence) VALUES (?,?,?,?,?)",
                (self.target, f.get("severity",""), f.get("issue","") or f.get("type",""),
                 f.get("url",""), json.dumps(f.get("evidence",""), default=str))
            )
            self._db.commit()
        except Exception:
            pass
