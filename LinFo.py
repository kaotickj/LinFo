#!/usr/bin/env python3
# Script: LinFo v 0.1
# Author: kaotickj
# Website: https://github.com/kaotickj

import subprocess

####################
#  COLORS
####################
C = "\033"
RED = f"{C}[1;31m"
GREEN = f"{C}[1;32m"
YELLOW = f"{C}[1;33m"
BLUE = f"{C}[1;34m"
LIGHT_MAGENTA = f"{C}[1;95m"
LIGHT_CYAN = f"{C}[1;96m"
LG = f"{C}[1;37m"  # LightGray
DG = f"{C}[1;90m"  # DarkGray
NC = f"{C}[0m"


def run_command(command):
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        return result.stdout.strip()
    else:
        return ""


def get_os_info():
    os_info = run_command("lsb_release -sd 2>/dev/null")
    if not os_info:
        os_info = run_command("sw_vers -productName 2>/dev/null")
    return os_info


def get_kernel_version():
    return run_command("uname -r")


def get_host_name():
    return run_command("hostname")


def get_uptime():
    return run_command("uptime -p")


def get_package_count():
    return run_command("dpkg-query -f '${binary:Package}\n' -W 2>/dev/null | wc -l")


def get_desktop_environment():
    return run_command("echo $XDG_CURRENT_DESKTOP | tr '[:upper:]' '[:lower:]'")


def get_window_manager():
    return run_command("echo $XDG_SESSION_TYPE")


def get_theme():
    return run_command("gsettings get org.gnome.desktop.interface gtk-theme")


def get_icon_theme():
    return run_command("gsettings get org.gnome.desktop.interface icon-theme")


def get_resolution():
    return run_command("xdpyinfo | awk '/dimensions:/ {print $2}'")


def get_terminal():
    return run_command("echo $TERM")


def get_shell():
    return run_command("basename $SHELL")


def get_cpu_info():
    return run_command("lscpu | awk -F':' '/Model name/ {print $2}' | sed -e 's/^[ \\t]*//' 2>/dev/null")


def get_gpu_info():
    return run_command("lspci | grep -i 'vga\\|3d' | awk -F': ' '{print $2}' 2>/dev/null")


def get_memory_info():
    mem_total = run_command("grep MemTotal /proc/meminfo | awk '{print $2/1024/1024 \"GB\"}' 2>/dev/null")
    return f"{mem_total} (approximate)"


def get_disk_usage():
    return run_command("df -h --total 2>/dev/null | awk '/total/ {print $2 \" used, \" $4 \" free\"}'")


def get_interfaces():
    return run_command("ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo'")


os = get_os_info()
kernel = get_kernel_version()
host = get_host_name()
uptime = get_uptime()
packages = get_package_count()
de = get_desktop_environment()
wm = get_window_manager()
theme = get_theme()
icon_theme = get_icon_theme()
resolution = get_resolution()
terminal = get_terminal()
shell = get_shell()
cpu = get_cpu_info()
gpu = get_gpu_info()
memory = get_memory_info()
disk = get_disk_usage()
interfaces = get_interfaces()

print()
print(f"\n\n{YELLOW}             ⚙️    LinFo   ⚙️")
print(f"{LIGHT_MAGENTA}      🕵🔎 Powered by  KaotickJ 👽          \n")
print(f"{GREEN}    🐧 OS:{LIGHT_CYAN} {os}")
print(f"{GREEN}    🏠 Host:{LIGHT_CYAN} {host}")
print(f"{GREEN}    🌽 Kernel:{LIGHT_CYAN} {kernel}")
print(f"{GREEN}    ⏲️  Uptime:{LIGHT_CYAN} {uptime}")
print(f"{GREEN}    📦 Packages:{LIGHT_CYAN} {packages}")
print(f"{GREEN}    🖥️  Desktop:{LIGHT_CYAN} {de}")
print(f"{GREEN}    🖼️  Window Mngr:{LIGHT_CYAN} {wm}")
print(f"{GREEN}    🎭 Theme:{LIGHT_CYAN} {theme}")
print(f"{GREEN}    🎨 Icons:{LIGHT_CYAN} {icon_theme}")
print(f"{GREEN}    📐 Resolution:{LIGHT_CYAN} {resolution}")
print(f"{GREEN}    💻 Terminal:{LIGHT_CYAN} {terminal}")
print(f"{GREEN}    🔨 Shell:{LIGHT_CYAN} {shell}")
print(f"{GREEN}    ⚡️ CPU:{LIGHT_CYAN} {cpu}")
print(f"{GREEN}    🎮 GPU:{LIGHT_CYAN} {gpu}")
print(f"{GREEN}    🧠 RAM:{LIGHT_CYAN} {memory}")
print(f"{GREEN}    💾 Disk Usage:{LIGHT_CYAN} {disk}\n")
print(f"{GREEN}    🌐 Interfaces:")

for interface in interfaces.split('\n'):
    ip = run_command(f"ip -o addr show dev {interface} | awk '$3 == \"inet\" {{print $4}}'")
    print(f"        {GREEN}🔗 {interface}: {LIGHT_CYAN}{ip}{NC}")


# ASCII art
print(f"{RED}")
print("    ██▓     ██▓ ███▄    █   █████▒▒█████")
print("   ▓██▒    ▓██▒ ██ ▀█   █ ▓██   ▒▒██▒  ██▒")
print("   ▒██░    ▒██▒▓██  ▀█ ██▒▒████ ░▒██░  ██▒")
print("   ▒██░    ░██░▓██▒  ▐▌██▒░▓█▒  ░▒██   ██░")
print("   ░██████▒░██░▒██░   ▓██░░▒█░   ░ ████▓▒░")
print("   ░ ▒░▓  ░░▓  ░ ▒░   ▒ ▒  ▒ ░   ░ ▒░▒░▒░")
print("   ░ ░ ▒  ░ ▒ ░░ ░░   ░ ▒░ ░       ░ ▒ ▒░")
print("     ░ ░    ▒ ░   ░   ░ ░  ░ ░   ░ ░ ░ ▒")
print(
    f"      🎈🎈🎈 {LIGHT_CYAN}y{YELLOW}O{BLUE}u{LIGHT_MAGENTA}'L{RED}l{YELLOW} f{LIGHT_CYAN}L{RED}o{LIGHT_CYAN}A{YELLOW}t{GREEN} {BLUE}t{LIGHT_MAGENTA}O{GREEN}o! 🎈🎈🎈        {NC}")
