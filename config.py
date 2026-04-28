import os

class Config:
    USER_AGENT    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    TIMEOUT       = 10
    MAX_PAGES     = 40
    REPORT_DIR    = "reports"
    DATA_DIR      = "data"
    DB_PATH       = "data/results.db"
    AI_MEMORY     = "data/ai_memory.json"
    NIKTO_PATH    = "nikto"
    GOBUSTER_PATH = "gobuster"

    @staticmethod
    def ensure_dirs():
        for d in [Config.REPORT_DIR, Config.DATA_DIR]:
            os.makedirs(d, exist_ok=True)
