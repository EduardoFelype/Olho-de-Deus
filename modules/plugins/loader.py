import os, importlib
from modules.plugins.base_plugin import BasePlugin

def load_plugins() -> list[BasePlugin]:
    plugins  = []
    skip     = {"loader.py","base_plugin.py","__init__.py"}
    pkg_path = os.path.join(os.path.dirname(__file__))

    for fname in os.listdir(pkg_path):
        if not fname.endswith(".py") or fname in skip:
            continue
        mod_name = f"modules.plugins.{fname[:-3]}"
        try:
            mod = importlib.import_module(mod_name)
            for attr in dir(mod):
                obj = getattr(mod, attr)
                try:
                    if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                        plugins.append(obj())
                except TypeError:
                    pass
        except Exception:
            pass
    return plugins
