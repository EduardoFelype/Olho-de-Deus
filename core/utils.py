import requests
import warnings
from colorama import Fore, Style
from config import Config

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def safe_request(url, method="GET", data=None, headers=None, timeout=None):
    try:
        h = {"User-Agent": Config.USER_AGENT}
        if headers:
            h.update(headers)
        return requests.request(
            method, url, headers=h, data=data,
            timeout=timeout or Config.TIMEOUT, verify=False
        )
    except Exception:
        return None

def print_status(msg, level="INFO"):
    clr = {"INFO": Fore.CYAN, "SUCCESS": Fore.GREEN, "WARN": Fore.YELLOW,
           "ERROR": Fore.RED, "CRIT": Fore.MAGENTA}
    sym = {"INFO": "[*]", "SUCCESS": "[+]", "WARN": "[!]", "ERROR": "[-]", "CRIT": "[!!]"}
    print(f"{clr.get(level, Fore.WHITE)}{sym.get(level,'[*]')} {msg}{Style.RESET_ALL}")
