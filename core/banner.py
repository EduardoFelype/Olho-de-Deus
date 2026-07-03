from colorama import Fore, Style, init
init()

def show_banner():
    print(f"""{Fore.CYAN}
 ██████╗ ██╗     ██╗  ██╗ ██████╗     ██████╗ ███████╗    ██████╗ ███████╗██╗   ██╗███████╗
██╔═══██╗██║     ██║  ██║██╔═══██╗    ██╔══██╗██╔════╝    ██╔══██╗██╔════╝██║   ██║██╔════╝
██║   ██║██║     ███████║██║   ██║    ██║  ██║█████╗      ██║  ██║█████╗  ██║   ██║███████╗
██║   ██║██║     ██╔══██║██║   ██║    ██║  ██║██╔══╝      ██║  ██║██╔══╝  ██║   ██║╚════██║
╚██████╔╝███████╗██║  ██║╚██████╔╝    ██████╔╝███████╗    ██████╔╝███████╗╚██████╔╝███████║
 ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═════╝ ╚══════╝    ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
{Fore.RED}
        👁  OLHO DE DEUS  v3.0  —  AI-Powered Pentest Framework
{Fore.WHITE}        Pipeline: Tradicional  |  Agressivo  |  IA
        Autor  : Eduardo Felype  |  Uso exclusivo em alvos autorizados
{Style.RESET_ALL}""")
