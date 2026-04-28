class BasePlugin:
    name     = "base"
    severity = "INFO"

    def run(self, url: str, response) -> dict | None:
        """Retorna dict com finding ou None."""
        return None
