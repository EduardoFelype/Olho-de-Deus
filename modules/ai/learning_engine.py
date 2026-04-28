import json, os
from config import Config

class LearningEngine:
    def __init__(self):
        self.path   = Config.AI_MEMORY
        self.memory = self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def learn(self, issue: str):
        self.memory[issue] = self.memory.get(issue, 0) + 1
        self._save()

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.memory, f, indent=2, ensure_ascii=False)

    def top_issues(self, n=10):
        return sorted(self.memory.items(), key=lambda x: x[1], reverse=True)[:n]

    def is_recurring(self, issue: str) -> bool:
        return self.memory.get(issue, 0) >= 2
