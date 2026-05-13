#!/usr/bin/env python3
import os, sys, socket, time, subprocess, ipaddress, random, shutil, platform, base64
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.live import Live
from osint import *
from Wifi import *
from TCP import *
from rich.text import Text
from rich.console import Console
from rich.align import Align
from rich.table import Table
from rich.prompt import Prompt

# constant
COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    389,
    443,
    445,
    465,
    587,
    636,
    993,
    995,
    1080,
    1433,
    1521,
    2222,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    8888,
    9200,
    9300,
    27017,
    28017,
]
TIMEOUT = 10
VERSION = 1.4
USER = ""


def clinput(s):
    return s.encode("utf-8", "ignore").decode("utf-8")


def WERSA(target, tool_ids):
    t = build_target(target)

    for tool in TOOLS:
        if tool[0] in tool_ids:
            print(f"\n──────── {tool[1]} ────────")
            try:
                print(tool[4](t))
            except Exception as e:
                print(err(str(e)))


# COLORS
class C:
    LM = "\033[92m"  # lime / bright green
    GR = "\033[32m"  # green
    DK = "\033[2;32m"  # dark green
    BD = "\033[1m"  # bold
    RS = "\033[0m"  # reset
    YW = "\033[93m"  # yellow (warnings)
    RE = "\033[91m"  # red (errors)
    WH = "\033[97m"  # white
    DM = "\033[2m"  # dim
    BK = "\033[90m"  # dark gray


def lm(s):
    return f"{C.LM}{s}{C.RS}"


def gr(s):
    return f"{C.GR}{s}{C.RS}"


def dk(s):
    return f"{C.DK}{s}{C.RS}"


def yw(s):
    return f"{C.YW}{s}{C.RS}"


def rd(s):
    return f"{C.RE}{s}{C.RS}"


def bd(s):
    return f"{C.BD}{s}{C.RS}"


def dm(s):
    return f"{C.DM}{s}{C.RS}"


def cmd(x):
    return subprocess.getoutput(x)


def is_kali():
    return os.path.exists("/etc/kali-release")


def parse_date(date_str: str) -> Optional[Tuple[int, int, int]]:
    try:
        parts = date_str.strip().split("-")
        if len(parts) != 3:
            return None
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except:
        return None


def encrypt_message(
    message: str, start_date: Tuple[int, int, int], end_date: Tuple[int, int, int]
) -> str:
    cipher = TPC(rule="shortest")
    encrypted_bytes, _, _ = cipher.enc_pack(message, start_date, end_date)
    return base64.b64encode(encrypted_bytes).decode()


def decrypt_message(
    encrypted_b64: str, start_date: Tuple[int, int, int], end_date: Tuple[int, int, int]
) -> str:
    encrypted_bytes = base64.b64decode(encrypted_b64)
    cipher = TPC(rule="shortest")
    decrypted, _, _ = cipher.dec_pack(encrypted_bytes, start_date, end_date)
    return decrypted


def run_selected_tools(target, tool_ids):
    t = build_target(target)
    satarget = target.encode("utf-8", "ignore").decode("utf-8")
    print(f"\n[ Running {len(tool_ids)} tools on: {satarget} ]\n")

    for tool in TOOLS:
        tool_id, name, category, platform, func, desc = tool

        if tool_id not in tool_ids:
            continue

        # ignore kali tools if =/ kali
        if platform == "kali" and not is_kali():
            continue

        console.print(Align.center(f"[#E60000]──────── {name} ────────[/#E60000]"))
        try:
            print(func(t))
        except Exception as e:
            print(err(str(e)))


def build_target(target):
    raw = target
    target = clinput(target).strip()

    # if its like a domain then do
    is_likely_web = ("." in target and " " not in target) or target.replace(
        ".", ""
    ).isdigit()

    if is_likely_web:
        try:
            parsed = urlparse(target if "://" in target else f"http://{target}")
            host = parsed.netloc or parsed.path
            host = cldomain(host)
        except Exception:
            host = target
    else:
        # treat raw
        return {
            "input": raw,
            "url": None,
            "host": None,
            "domain": None,
            "ip": None,
            "is_ip": False,
        }

    # detect ip
    try:
        socket.inet_aton(host)
        is_ip = True
        ip = host
    except:
        is_ip = False
        try:
            ip = socket.gethostbyname(host)
        except:
            ip = None

    return {  # return the result
        "input": raw,
        "url": f"http://{host}",
        "host": host,
        "domain": host,
        "ip": ip,
        "is_ip": is_ip,
    }


def run_osint():
    target = input("Enter domain or IP: ")
    t = build_target(target)

    for tool in TOOLS:
        func = tool[4]
        name = tool[1]

        print(f"\n== {name} ==")
        try:
            print(func(t))
        except Exception as e:
            print(err(str(e)))


def sport(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                return port
    except:
        pass
    return None


def sports(host):
    print(f"\nScanning on {host}...\n")

    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(sport, host, p) for p in COMMON_PORTS]

        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"Port {result} open")

    if not open_ports:
        print("No ports open")


def platform_type():
    sys_name = platform.system().lower()

    if "microsoft" in platform.uname().release.lower():
        return "wsl"

    if sys_name == "windows":
        return "windows"

    if "android" in platform.uname().release.lower():
        return "termux"

    return "linux"


def KAJWSNXA(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False


def generate_random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def X4():
    ip = cmd("hostname -I | awk '{print $1}'")
    parts = ip.strip().split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.xxx.xxx"
    return "hidden"


def XLXWOPO():
    while True:
        clear()

        console.print(
            Align.center(
                "┌────────────────────┐\n"
                "│ [#E60000]Choose a category[/#E60000]  │\n"
                "├────────────────────┤\n"
                "│ Free stuffs (01)   │\n"
                "│ Zphisher (02)      │\n"
                "│ OSINT (03)         │\n"
                "│ Botnet flood (04)  │\n"
                "│ Encrypt (05)       │\n"
                "└────────────────────┘"
            )
        )
        category = Prompt.ask(
            "> ",
            choices=["01", "1", "02", "2", "03", "3", "04", "4", "05", "5"],
            show_choices=False,
            default="01",
            show_default=False,
        )
        if category in ("1", "01"):
            while True:
                try:
                    clear()
                    console.print(
                        "Free [#E60000]Temporary Email[/#E60000] at 'https://temp-mail.org/en/' "
                    )
                    console.print(
                        "Free [#E60000]Proxy Generator[/#E60000] at 'https://proxygen.lovable.app' "
                    )
                    console.print(
                        "Free [#E60000]Anonymous Information Leak Dumpster[/#E60000] at 'https://leak-bin.onrender.com' , 'https://doxbin.com/home' "
                    )
                    answer = Prompt.ask(
                        "Return (00)> ",
                        choices=["0", "00"],
                        default="0",
                        show_choices=False,
                        show_default=False,
                    )
                    if answer in ("0", "00"):
                        break
                    else:
                        continue
                except KeyboardInterrupt:
                    break
        elif category in ("2", "02"):
            continue
        elif category in ("3", "03"):
            while True:
                try:
                    clear()
                    console.print(
                        "┌───────────────────────────────────┐",
                        f"\n│What do you want to find, [#E60000]hacker[/#E60000]?  │",
                        "\n│Person name [#E60000](01)[/#E60000]                   │",
                        "\n│Website [#E60000](02)[/#E60000]                       │",
                        "\n│IP [#E60000](03)[/#E60000]                            │",
                        "\n│Username [#E60000](04)[/#E60000]                      │",
                        "\n│Keyword [#E60000](05)[/#E60000]                       │",
                        "\n│SSID [#E60000](06)[/#E60000]                          │",
                        "\n│BSSID [#E60000](07)[/#E60000]                         │",
                        "\n│Address [#E60000](08)[/#E60000]                       │",
                        "\n│List tools [#E60000](99)[/#E60000]                    │",
                        "\n│Return [#d62e18](00)[/#d62e18]                        │",
                        "\n└───────────────────────────────────┘",
                        end="",
                    )
                    console.print(
                        "\n\nYes, i want to find [#E60000]everything[/#E60000] about",
                        end="",
                    )
                    choice = Prompt.ask(
                        ">",
                        choices=[
                            "01",
                            "1",
                            "02",
                            "2",
                            "03",
                            "3",
                            "04",
                            "4",
                            "05",
                            "5",
                            "06",
                            "6",
                            "07",
                            "7",
                            "08",
                            "8",
                            "99",
                            "00",
                            "0",
                        ],
                        show_choices=False,
                    )
                    if choice in ("0", "00"):
                        break
                    elif choice in ("1", "01"):
                        target = input("\nEnter their name>  ")  # OSINT the name

                    elif choice in ("2", "02"):
                        target = input("\nEnter domain (example.com)>  ")

                    elif choice in ("3", "03"):
                        target = input("\nEnter their public Ip>  ")

                    elif choice in ("4", "04"):
                        target = clinput(
                            input("\nEnter their username, any username>  ")
                        )

                    elif choice in ("5", "05"):
                        target = input("\nEnter the keyword to search>  ")
                    elif choice in ("6", "06"):
                        target = input("\nEnter their SSID (name of network)>  ")
                    elif choice in ("7", "07"):
                        target = input("\nEnter their BSSID (Id of their router)>  ")

                    elif choice in ("8", "08"):
                        target = input("\nEnter their address>  ")
                        target = target.replace(",", "").replace(".", "")
                    elif choice == "99":
                        while True:

                            clear()
                            names = [tool[1] for tool in TOOLS]
                            for name in names:
                                print(name)
                            console.print(
                                f"\nTotal tools: [#E60000]{len(TOOLS)}[/#E60000]",
                            )
                            back = Prompt.ask(
                                "Back (00)>",
                                choices=["0", "00"],
                                show_choices=False,
                                default="0",
                                show_default=False,
                            )
                            if back in ("0", "00"):
                                break
                        continue
                    else:
                        print("Invalid choice")
                        continue
                    if choice.isdigit():
                        choice = str(int(choice))  # fixed 0x problem
                    tool_ids = OSINT_PRESETS.get(choice, [])

                    if not tool_ids:
                        print("Error, tool(s) not assigned")
                    else:
                        run_selected_tools(target, tool_ids)
                    input("\nPress key Enter to return...")
                except KeyboardInterrupt:
                    break
        elif category in ("4", "04"):
            continue
        elif category in ("5", "05"):
            while True:
                clear()
                console.print(
                    Align.center(
                        "┌─────────────────────┐\n"
                        "│ [#E60000]Encryption Tools[/#E60000]    │\n"
                        "├─────────────────────┤\n"
                        "│ Encrypt message (01)│\n"
                        "│ Decrypt message (02)│\n"
                        "│ Return (00)         │\n"
                        "└─────────────────────┘"
                    )
                )
                option = Prompt.ask(
                    "> ",
                    choices=["01", "1", "02", "2", "00", "0"],
                    show_choices=False,
                )

                if option in ("0", "00"):
                    break
                elif option in ("1", "01"):
                    clear()
                    console.print("[#E60000]Encrypt a message[/#E60000]\n")
                    message = Prompt.ask("Enter your message")
                    start = Prompt.ask("Start date (YYYY-MM-DD)")
                    end = Prompt.ask("End date (YYYY-MM-DD)")

                    start_tuple = parse_date(start)
                    end_tuple = parse_date(end)

                    if start_tuple and end_tuple:
                        encrypted = encrypt_message(message, start_tuple, end_tuple)
                        console.print(f"\n[#00ff00]Encrypted:[/#00ff00] {encrypted}")

                    else:
                        console.print(
                            "[#E60000]invalid format, use YYYY-MM-DD format[/#E60000]"
                        )
                    input("\nPress Enter to continue...")

                elif option in ("2", "02"):
                    clear()
                    console.print(
                        "[#E60000]Decrypt a string with my technique[/#E60000]\n"
                    )
                    ciphertext = Prompt.ask("Enter the string")
                    start = Prompt.ask("Start date (YYYY-MM-DD)")
                    end = Prompt.ask("End date (YYYY-MM-DD)")

                    start_tuple = parse_date(start)
                    end_tuple = parse_date(end)

                    if start_tuple and end_tuple:
                        try:
                            decrypted = decrypt_message(
                                ciphertext, start_tuple, end_tuple
                            )
                            console.print(
                                f"\n[#00ff00]Decrypted:[/#00ff00] {decrypted}"
                            )
                        except Exception as e:
                            console.print(f"[#E60000]decryption failed:{e}[/#E60000]")
                    else:
                        console.print(
                            "[#E60000]invalid format, use YYYY-MM-DD format[/#E60000]"
                        )
                    input("\nPress Enter to continue...")
        else:
            break


def fsociety_boot(duration=3):
    console.show_cursor(False)

    try:
        logo = """\
                        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                        @@                  @@@@@@@@@@@                 @@
                        @@-         @@@@@@@@@@@@@@@@@@@@@@@@@@          @@
                        @@@      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      @@
                        @#@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    @@
                        @@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@
                        @@ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @@
                        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                        @@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@
                        @@    @@@@         @@@@@@@@@@@@@         @@@@   @@
                        @@@@@ @   @@@@@       @@@@@@@      @@@@@@  @@  @@@
                        @@    @@@@@@@@@@@@      @@@      @@@@@@@@@@@@   @@
                        @@@  @@@@@@@@@@@@@@@   @@@@   @@@@@@@@@@@@@@@@  @@
                        @@@@@@@  @@@@@.   @@@@@@@@@@@@@@@    @@@@@ @@@@@@@
                        @@@@@@@ @@@@        @@@@@@@@@@         @@@ @@@@@@@
                        @@@@@@@@@@@         @@@ @@@@@@          @@@@@@@@@@
                        @@@@@@@@@ @@@@@@@@ :@@@ @@@ @@@ %@@@@@@@@@@@@@@@@@
                        @@@@@@@@@@@@@@@@@@@@@* @@@@@  @@@@@@@@@@@@@@@@@@@@
                        @@@@@@@ -@@@@@@@@@@@ @@@@@@@@@ @@@@@@@@@@@  @@@@@@
                        @@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@@
                        @@@@    @@@@@@@@@@    @@@@@@     @@@@@@@@@@    @@@
                        @@@@      @@@@          @@           @@@@      @@@
                        @@@@                                           @@@
                        @@@@                                          @@@@
                        @@@ @                                       @@@ @@
                        @@@  @@@@@@@  @@@@@@@@@      @@@@@@     @@@@@   @@
                        @@@   @@@@ @@@@@@                 @@@@@@@@@@@   @@
                        @@@    @@@@@@@@@@@              @@@@@@@@@@@@    @@
                        @@@    @@@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@    @@
                        @@@    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     @@
                        @@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     @@
                        @@@      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      @@
                        @@@       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       @@
                        @@@         @@@@@@@@@@@@@@@@@@@@@@@@@@@         @@
                        @@@           @@@@@@@@@@@@@@@@@@@@@@@           @@
                        @@@             @@@@@@@@@@@@@@@@@@@             @@
                        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

                        
                            @@   @@                 @
                           @#   @      @@@    @          @@@    @@
                          @@@+   @ @@ @@ @@ @@ @@  @@   @@ @@  -@@-  @@  @@
                           @       @  @@ @@ @@     -@   @@      @     @  @@
                          @@@@  =@@@   @@@   @@@@ @@@@@  @@@=    @@.   @@@
                                                                     @@@@
"""

        charset = "@#$%&*+=~<>-:/\\|"
        width, height = shutil.get_terminal_size()

        def frame():
            return Text(
                "\n".join(
                    "".join(random.choice(charset) for _ in range(width))
                    for _ in range(height)
                ),
                style="red",
            )

        with Live(frame(), console=console, screen=True, refresh_per_second=25) as live:
            start = time.time()
            while time.time() - start < duration:
                time.sleep(0.03)
                live.update(frame())
        console.clear()
        time.sleep(0.2)

        for line in logo.split("\n"):
            console.print(Align.center(line, vertical="middle"), style="red")
            time.sleep(0.05)
        time.sleep(4)

    finally:
        console.show_cursor(True)


def osdev():
    type = platform_type().lower().strip()
    is_unix = type in ["linux", "wsl", "termux"]
    linux = [
        "::::::::::::::[#1C1C1C]x$$$$$$+[/#1C1C1C]::::::::::::::",
        "::::::::::::[#1C1C1C];$$$$$$$xX$+[/#1C1C1C]::::::::::::",
        "::::::::::::[#1C1C1C]X$$$$$$$$$$$;[/#1C1C1C]:::::::::::",
        "::::::::::::[#1C1C1C]$[/#1C1C1C][#EDEDED]Xx[/#EDEDED][#1C1C1C]$$$[/#1C1C1C][#EDEDED]X+;[/#EDEDED][#1C1C1C]$$$$[/#1C1C1C]:::::::::::",
        "::::::::::::[#1C1C1C]$[/#1C1C1C][#EDEDED]xX:[/#EDEDED][#1C1C1C]$[/#1C1C1C][#EDEDED]x+[/#EDEDED][#EDEDED]$X+[/#EDEDED][#1C1C1C]$$$[/#1C1C1C]:::::::::::",
        "::::::::::::[#1C1C1C]$[/#1C1C1C][#FDF001]+x;;;;x;X[/#FDF001][#1C1C1C]$$$[/#1C1C1C]:::::::::::",
        "::::::::::::[#1C1C1C]X[/#1C1C1C][#FDF001]++;;;;;+X[/#FDF001][#1C1C1C]$$$[/#1C1C1C]:::::::::::",
        "::::::::::::[#1C1C1C]X[/#1C1C1C][#FDF001]xx+++++;[/#FDF001][#1C1C1C]+$Xx$[/#1C1C1C]::::::::::",
        ":::::::::::[#1C1C1C]+$[/#1C1C1C][#FFFFFF]:[/#FFFFFF][#D0D0D0];;;;;:[/#D0D0D0][#FFFFFF]::[/#FFFFFF][#1C1C1C]+$$$X[/#1C1C1C]:::::::::",
        "::::::::::[#1C1C1C]$$[/#1C1C1C][#FFFFFF]:::::::::::[/#FFFFFF][#1C1C1C]x$$$$;[/#1C1C1C]:::::::",
        "::::::::[#1C1C1C]x$$[/#1C1C1C][#FFFFFF]::::::::::::[/#FFFFFF][#1C1C1C];$$$$$$[/#1C1C1C]::::::",
        ":::::::[#1C1C1C];$$x[/#1C1C1C][#FFFFFF]::::::::::::::[/#FFFFFF][#1C1C1C]X$$$$X[/#1C1C1C]:::::",
        ":::::::[#1C1C1C]$$x[/#1C1C1C][#FFFFFF]::::::::::::::::[/#FFFFFF][#1C1C1C]X$$$$x[/#1C1C1C]::::",
        "::::::[#1C1C1C]XX$[/#1C1C1C][#FFFFFF]:::::::::::::::::[/#FFFFFF][#1C1C1C]x$$$$$[/#1C1C1C]::::",
        ":::::[#1C1C1C]x$$+[/#1C1C1C][#FFFFFF]:::::::::::::::::[/#FFFFFF][#1C1C1C]x$$$$$+[/#1C1C1C]:::",
        ":::::[#1C1C1C]$$X+[/#1C1C1C][#FFFFFF]:::::::::::::::::[/#FFFFFF][#1C1C1C]x$X$$$;[/#1C1C1C]:::",
        ":::::[#1C1C1C];;;Xx[/#1C1C1C][#FFFFFF]::::::::::::::[/#FFFFFF][#1C1C1C]+;x$$$$x[/#1C1C1C]::::",
        ":[#FDF001]+;;;;;;;[/#FDF001][#1C1C1C]x$X[/#1C1C1C][#FFFFFF]::::::::::::[/#FFFFFF][#1C1C1C]+;+$$X+;;[/#1C1C1C]:::",
        ":[#FDF001];;;;;;;;;[/#FDF001][#1C1C1C]x$$+[/#1C1C1C][#FFFFFF]:::::::::[/#FFFFFF][#FDF001];+;;[/#FDF001]++[#FDF001];;;;;[/#FDF001]::",
        ":[#FDF001]+;;;;;;;;;[/#FDF001][#1C1C1C]+;[/#1C1C1C][#FFFFFF]:::::::::[/#FFFFFF][#1C1C1C]+$[/#1C1C1C][#FDF001]x;;;;;;;;;;[/#FDF001]+",
        "+[#FDF001];;;;;;;;;;;[/#FDF001][#1C1C1C]+x[/#1C1C1C][#FFFFFF];::::[/#FFFFFF][#1C1C1C];X$$$[/#1C1C1C][#FDF001]x;;;;;;++++[/#FDF001]:",
        "[#FDF001];++++++;;;;;+[/#FDF001][#1C1C1C]X$$$$$$$$$$[/#1C1C1C][#FDF001]x+++++x[/#FDF001]:::::",
        ":::::::[#FDF001];xxxxx[/#FDF001][#1C1C1C]:::::::::::[/#1C1C1C][#FDF001]XXxxx[/#FDF001]:::::::",
    ]
    sycmd = [
        f"User: {cmd('whoami')}",
        f"Host: {cmd('hostname')}",
        f"OS: {cmd('uname -s') if is_unix else cmd('$env:OS')}",
        f"Kernel: {cmd('uname -r') if is_unix else cmd('systeminfo | findstr /B /C:\"OS Version\"')}",
        f"Arch: {cmd('uname -m') if is_unix else cmd('$env:PROCESSOR_ARCHITECTURE')}",
        f"CPU: {(
        cmd('wmic cpu get name').splitlines()[1].strip()
        if type == "windows"
        else cmd('getprop ro.product.cpu.abi').strip()
        if type == "termux"
        else (
            lambda x: x.split(':',1)[1].strip() if ':' in x else 'Unknown'
        )(cmd('grep \"model name\" /proc/cpuinfo | head -1'))
        if is_unix
        else 'Unknown'
    )}",
        f"GPU: {(
        cmd('wmic path win32_VideoController get name').splitlines()[1].strip()
        if type == 'windows'
        else cmd('nvidia-smi --query-gpu=name --format=csv,noheader').strip()
        if is_unix
        else 'N/A'
    )}",
        f"RAM: {(
        cmd('wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /Value')
        if type == 'windows'
        else cmd('free -h | grep Mem')
        if is_unix
        else 'N/A'
    )}",
        f"Disk: {(
        cmd('wmic logicaldisk get size,freespace,caption')
        if type == 'windows'
        else cmd('df -h /data')
        if type == 'termux'
        else cmd('df -h /')
        if is_unix
        else 'N/A'
    )}",
        f"Uptime: {(
        cmd('net stats workstation')
        if type == 'windows'
        else cmd('uptime')
        if type == 'termux'
        else cmd('uptime -p')
        if is_unix
        else 'N/A'
    )}",
        f"IP: {X4()}",
    ]

    console = Console()

    def render(linux, sys):
        table = Table(show_header=False, box=None, pad_edge=False)

        table.add_column("left", justify="left")
        table.add_column("right", justify="left")

        for i in range(max(len(linux), len(sys))):
            left = linux[i] if i < len(linux) else ""
            right = sys[i] if i < len(sys) else ""
            table.add_row(left, right)

        console.print(table)

    render(linux, sycmd)


def clear():
    os.system("clear")


console = Console()


def main():
    global USER, VERSION
    clear()
    fsociety_boot()
    clear()
    art = """
░██╗    ░██╗ ███████╗ ███████╗ ███████╗ ███████╗ ██╗  ██╗ ███╗   ███╗  █████╗  ███╗   ██╗
░██║    ░██║ ██╔════╝ ██╔════╝ ██╔════╝ ██╔════╝ ╚██╗██╔╝ ████╗ ████║ ██╔══██╗ ████╗  ██║
░██║ █╗ ░██║ █████╗   ███████╗ ███████╗ █████╗    ╚███╔╝  ██╔████╔██║ ███████║ ██╔██╗ ██║
░██║███╗░██║ ██╔══╝   ╚════██║ ╚════██║ ██╔══╝    ██╔██╗  ██║╚██╔╝██║ ██╔══██║ ██║╚██╗██║
░╚███╔███╔╝  ███████╗ ███████║ ███████║ ███████╗ ██╔╝ ██╗ ██║ ╚═╝ ██║ ██║  ██║ ██║ ╚████║
░ ╚══╝╚══╝   ╚══════╝ ╚══════╝ ╚══════╝ ╚══════╝ ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═══╝
"""
    for line in art.split("\n"):
        console.print(Align.center(line, vertical="middle"), style="#E60000")
        time.sleep(0.09)
    console.print(
        Align.center(
            f"[#E60000]Tool by[/#E60000] [#3360e8]LostEyes[/#3360e8][#E60000], version[/#E60000] [#3360e8]{VERSION}[/#3360e8]"
        )
    )
    time.sleep(1)
    osdev()
    USER = cmd("whoami")
    console.print("Press key [#E60000]Enter[/#E60000] to continue...", end="")
    input()
    XLXWOPO()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[#E60000]Exited[/#E60000] program.")
