#!/bin/bash
# Script: LinFo v0.5
# Author: Kaotick Jay
# Website: https://github.com/kaotickj

####################
#  CONFIG
####################
SHOW_ART=1
SKIP_IP=0
RUN_SCAN=0
RUN_LOOT=0

###########################################
#---------------  Colors  ----------------#
###########################################

C=$(printf '\033')

# Foreground + Background Colors
FGR="${C}[48;5;196m"        # Red BG
FGG="${C}[48;5;22m"         # Green BG
FGB="${C}[48;5;34m"         # Blue BG
FGC="${C}[48;5;237m"        # Gray BG

# Standard Foreground Colors
RED="${C}[1;31m"
GREEN="${C}[1;32m"
YELLOW="${C}[1;33m"
BLUE="${C}[1;34m"
LIGHT_MAGENTA="${C}[1;95m"
LIGHT_CYAN="${C}[1;96m"
LG="${C}[1;37m"
DG="${C}[1;90m"

# SED-style Highlight Colors
SED_RED="${RED}&${C}[0m"
SED_GREEN="${GREEN}&${C}[0m"
SED_YELLOW="${YELLOW}&${C}[0m"
SED_RED_YELLOW="${C}[1;31;103m&${C}[0m"
SED_BLUE="${BLUE}&${C}[0m"
SED_LIGHT_MAGENTA="${LIGHT_MAGENTA}&${C}[0m"
SED_LIGHT_CYAN="${LIGHT_CYAN}&${C}[0m"
SED_LG="${LG}&${C}[0m"
SED_DG="${DG}&${C}[0m"

# Text Styles
UNDERLINED="${C}[4m"
ITALIC="${C}[3m"
ITALIC_BLUE="${BLUE}${ITALIC}"

# Reset
NC="${C}[0m"

if [[ $EUID -ne 0 ]]; then
  echo -e "${YELLOW}Note:${NC} For full functionality, run as root."
  read -p "🔓 Would you like to rerun as root using sudo? [y/N]: " elevate
  if [[ "$elevate" =~ ^[Yy]$ ]]; then
    exec sudo "$0" "$@"
    exit
  fi
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scan)
      RUN_SCAN=1
      ;;
    --loot|--c2ready)
      RUN_LOOT=1
      ;;
    --fullscan)
      RUN_SCAN=1
      RUN_LOOT=1
      RUN_HARDENING=1
      SKIP_IP=1
      ;;
    --hardening-check) 
      RUN_HARDENING=1
      ;;
    --help|-h|--h)
	  cat << EOF
	${YELLOW}Usage:${NC} $0 [options]

	${LIGHT_MAGENTA}Options:${NC}
	  ${LIGHT_CYAN}--quiet${NC}          Run script in quiet mode (minimal output).
	  ${LIGHT_CYAN}--no-ip${NC}          Skip displaying network interface IP addresses.
	  ${LIGHT_CYAN}--raw${NC}            Output raw, uncolored text for easier parsing.
	  ${LIGHT_CYAN}--scan${NC}           Perform security scanning checks and display a security report.
	  ${LIGHT_CYAN}--loot, --c2ready${NC} Gather potential loot, indicators, and staging areas for C2 readiness.
	  ${LIGHT_CYAN}--hardening-check${NC} Check the system update status and hardening features.
	  ${LIGHT_CYAN}--fullscan${NC}       Run both --scan and --loot checks; skips IP info for speed.
	  ${LIGHT_CYAN}--help, -h${NC}       Show this help message and exit.

	${LIGHT_MAGENTA}Examples:${NC}
	  ${GREEN}$0 --scan${NC}
		  Run only the security scan report.

	  ${GREEN}$0 --loot${NC}
		  Run loot gathering report.

	  ${GREEN}$0 --fullscan${NC}
		  Run full security and loot reports in one execution.

	${YELLOW}Notes:${NC}
	  - Running with root privileges is recommended for full scan accuracy.
	  - Use --quiet to reduce output noise in automation contexts.

EOF
	  exit 0
	  ;;
    *)
      echo -e "${RED}Unknown option:${NC} $1"
      exit 1
      ;;
  esac
  shift
done

####################
#  FUNCTIONS
####################
get_os() {
  lsb_release -sd 2>/dev/null || grep -m1 '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"' || hostnamectl | grep "Operating System" | cut -d: -f2 | sed 's/^ *//'
}

get_cpu() {
  command -v lscpu &>/dev/null && lscpu | awk -F':' '/Model name/ {gsub(/^ +/, "", $2); print $2; exit}' || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//'
}

get_gpu() {
  command -v lspci &>/dev/null && lspci | grep -i 'vga\|3d' | awk -F': ' '{print $2}' | head -n1 || echo "N/A"
}

get_memory() {
  awk '/MemTotal/ {printf "%.2f GB", $2/1024/1024}' /proc/meminfo
}

get_disk() {
  df -h --total 2>/dev/null | awk '/total/ {print $2 " used, " $4 " free"}'
}

get_packages() {
  if command -v dpkg-query &>/dev/null; then
    dpkg-query -f '${binary:Package}\n' -W 2>/dev/null | wc -l
  elif command -v rpm &>/dev/null; then
    rpm -qa | wc -l
  else
    echo "?"
  fi
}

get_de() {
  echo "${XDG_CURRENT_DESKTOP:-$DESKTOP_SESSION}" | tr '[:upper:]' '[:lower:]'
}

get_resolution() {
  xdpyinfo 2>/dev/null | awk '/dimensions:/ {print $2}' || echo "N/A"
}

get_interfaces() {
  ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$'
}

get_interface_ip() {
  ip -o -4 addr show dev "$1" | awk '{print $4}' | head -n1
}

get_kernel_hardening() {
    echo ""

    echo -e "${YELLOW}    ##############################${NC}"
    echo -e "${YELLOW}    #  Kernel Security Features  #${NC}"
    echo -e "${YELLOW}    ##############################${NC}"

    # SELinux enforcement status
    if command -v getenforce &>/dev/null; then
        selinux_status=$(getenforce)
        echo -e "    🔐 SELinux Enforcement: ${LIGHT_CYAN}$selinux_status${NC}"
    else
        echo -e "    🔐 SELinux Enforcement: ${YELLOW}Not installed${NC}"
    fi

    # AppArmor status
    if [ -d /sys/module/apparmor ]; then
        apparmor_status="Enabled"
    else
        apparmor_status="Not detected"
    fi
    echo -e "    🛡️  AppArmor: ${LIGHT_CYAN}$apparmor_status${NC}"

    # Check for Yama LSM
    yama_status=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
    if [[ -n "$yama_status" ]]; then
        echo -e "    🛡️ Yama ptrace_scope: ${LIGHT_CYAN}$yama_status (0=off, 1=strict)${NC}"
    else
        echo -e "    🛡️ Yama ptrace_scope: ${YELLOW}Not available${NC}"
    fi

    # Kernel hardening flags from dmesg (SMEP, SMAP, NX)
    echo -e "    🔍 Kernel Hardening Flags:"
    dmesg | grep -E -i 'SMEP|SMAP|NX|stack protector' | head -10 | while read -r line; do
        echo -e "       ${LIGHT_CYAN}$line${NC}"
    done

    # Check if grsecurity is present
    if dmesg | grep -iq grsecurity; then
        echo -e "    🛡️  Grsecurity: ${GREEN}Detected${NC}"
    else
        echo -e "    🛡️  Grsecurity: ${YELLOW}Not detected${NC}"
    fi

    # Stack protector status
    stack_protector=$(grep CONFIG_CC_STACKPROTECTOR /boot/config-$(uname -r) 2>/dev/null || echo "Unknown")
    echo -e "    🛡️  Stack Protector Config: ${LIGHT_CYAN}$stack_protector${NC}"

    # NX bit (No Execute) support
    if grep -q nx /proc/cpuinfo 2>/dev/null; then
        echo -e "    💥 NX Bit support: ${GREEN}Yes${NC}"
    else
        echo -e "    💥 NX Bit support: ${YELLOW}No or Unknown${NC}"
    fi

    echo ""
}

loot_output_handler() {
    echo -e "${YELLOW}    The loot report can be very lengthy.${NC}"
    read -rp "${LIGHT_MAGENTA}    Would you like to save the loot output to a file? [y/N]: " save_choice
    if [[ "$save_choice" =~ ^[Yy]$ ]]; then
        local default_file="loot_report_$(date +%Y%m%d_%H%M%S).txt"
        read -rp "${LIGHT_MAGENTA}    Enter filename to save loot output [${default_file}]: " loot_file
        loot_file=${loot_file:-$default_file}

        # Check if file exists
        if [[ -e "$loot_file" ]]; then
            read -rp "${RED}    File '$loot_file' exists. Overwrite? [y/N]: ${NC}" overwrite_choice
            if ! [[ "$overwrite_choice" =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}    Aborting save. Output will be printed to terminal.${NC}"
                run_loot_gather
                return
            fi
        fi

        echo -e "${GREEN}    Saving loot output to: $loot_file${NC}"
        run_loot_gather > "$loot_file" 2>&1
        echo -e "${GREEN}    Loot report saved successfully.${NC}"
    else
        run_loot_gather
    fi
}

scan_output_handler() {
    echo -e "${YELLOW}    The scan report output may be lengthy.${NC}"
    read -rp "${LIGHT_MAGENTA}    Would you like to save the scan report output to a file? [y/N]: " save_choice
    if [[ "$save_choice" =~ ^[Yy]$ ]]; then
        local default_file="scan_report_$(date +%Y%m%d_%H%M%S).txt"
        read -rp "${LIGHT_MAGENTA}    Enter filename to save scan report [${default_file}]: " output_file
        output_file=${output_file:-$default_file}

        if [[ -e "$output_file" ]]; then
            read -rp "${RED}    File '$output_file' exists. Overwrite? [y/N]: ${NC}" overwrite_choice
            if ! [[ "$overwrite_choice" =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}    Aborting save. Scan report will be printed to terminal.${NC}"
                run_scan_report
                return
            fi
        fi

        echo -e "${GREEN}    Saving scan report to: $output_file${NC}"
        run_scan_report > "$output_file" 2>&1
        echo -e "${GREEN}    Scan report saved successfully.${NC}"
    else
        run_scan_report
    fi
}

firewall_check() {
    echo
    echo -e "  ${LIGHT_MAGENTA}    #  Firewall Check       #${NC}"

    local firewall_detected=false

    # Check for iptables
    if command -v iptables &>/dev/null; then
        echo -e "  ${GREEN}    🔥 iptables: Installed${NC}"
        firewall_detected=true
        if sudo iptables -L -n &>/dev/null; then
            echo -e "  ${GREEN}    🔒 iptables rules: Present${NC}"
        else
            echo -e "  ${RED}    🔓 iptables rules: None or cannot access rules (are you root?)${NC}"
        fi
    fi

    # Check for nftables
    if command -v nft &>/dev/null; then
        echo -e "  ${GREEN}    🔥 nftables: Installed${NC}"
        firewall_detected=true
        if sudo nft list ruleset &>/dev/null; then
            echo -e "  ${GREEN}    🔒 nftables rules: Present${NC}"
        else
            echo -e "  ${RED}    🔓 nftables rules: None or cannot access rules (are you root?)${NC}"
        fi
    fi

    # Check for ufw
    if command -v ufw &>/dev/null; then
        echo -e "  ${GREEN}    🛡️  UFW (Uncomplicated Firewall): Installed${NC}"
        firewall_detected=true
        if sudo ufw status | grep -q 'Status: active'; then
            echo -e "  ${GREEN}    🔒 UFW Status: Active${NC}"
        else
            echo -e "  ${RED}    🔓 UFW Status: Inactive${NC}"
            echo -e "      ${BLUE}Recommendation: Run 'sudo ufw enable' to activate.${NC}"
        fi
    fi

    # Check for firewalld
    if command -v firewall-cmd &>/dev/null; then
        echo -e "  ${GREEN}    🔥 firewalld: Installed${NC}"
        firewall_detected=true
        if sudo systemctl is-active firewalld &>/dev/null; then
            echo -e "  ${GREEN}    🔒 firewalld Status: Active${NC}"
        else
            echo -e "  ${RED}    🔓 firewalld Status: Inactive${NC}"
            echo -e "      ${BLUE}Recommendation: Run 'sudo systemctl enable --now firewalld' to activate.${NC}"
        fi
    fi

    if [ "$firewall_detected" = false ]; then
        echo -e "\n    ${RED}    No known firewall detected.${NC}"
        echo -e "    ${BLUE}    Recommendation: Install a firewall such as iptables, nftables, ufw, or firewalld.${NC}"
	echo -e "    ${YELLOW}  Installed firewall may not be detected if you are not running with root permission."
        echo -e "    ${FGR}${YELLOW}    If you are using a different firewall, you may ignore this recommendation if it is properly installed and enabled.${NC}"
    fi

}


hardening_output_handler() {
    echo -e "${YELLOW}    The hardening check report output may be lengthy.${NC}"
    read -rp "${LIGHT_MAGENTA}    Would you like to save the report output to a file? [y/N]: " save_choice
    if [[ "$save_choice" =~ ^[Yy]$ ]]; then
        local default_file="hardening_report_$(date +%Y%m%d_%H%M%S).txt"
        read -rp "${LIGHT_MAGENTA}    Enter filename to save scan report [${default_file}]: " output_file
        output_file=${output_file:-$default_file}

        if [[ -e "$output_file" ]]; then
            read -rp "${RED}    File '$output_file' exists. Overwrite? [y/N]: ${NC}" overwrite_choice
            if ! [[ "$overwrite_choice" =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}    Aborting save. Scan report will be printed to terminal.${NC}"
                run_hardening_check
                return
            fi
        fi

        echo -e "${GREEN}    Saving scan report to: $output_file${NC}"
        run_hardening_check > "$output_file" 2>&1
        echo -e "${GREEN}    Scan report saved successfully.${NC}"
    else
        run_hardening_check
    fi
}

fullscan_output_handler() {
    echo -e "${YELLOW}    The full scan output can be very lengthy.${NC}"
    read -rp "${LIGHT_MAGENTA}    Would you like to save the full scan output to a file? [y/N]: " save_choice
    if [[ "$save_choice" =~ ^[Yy]$ ]]; then
        local default_file="fullscan_report_$(date +%Y%m%d_%H%M%S).txt"
        read -rp "${LIGHT_MAGENTA}    Enter filename to save full scan output [${default_file}]: " output_file
        output_file=${output_file:-$default_file}

        if [[ -e "$output_file" ]]; then
            read -rp "${RED}    File '$output_file' exists. Overwrite? [y/N]: ${NC}" overwrite_choice
            if ! [[ "$overwrite_choice" =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}    Aborting save. Output will be printed to terminal.${NC}"
                run_scan_report
                echo
                run_loot_gather
                echo
                run_hardening_check
                return
            fi
        fi

        echo -e "${GREEN}    Saving full scan output to: $output_file${NC}"
        {
            run_scan_report
            echo
            run_loot_gather
            echo
            run_hardening_check
        } > "$output_file" 2>&1
        echo -e "${GREEN}    Full scan report saved successfully.${NC}"
    else
        run_scan_report
        echo
        run_loot_gather
        echo
        run_hardening_check
    fi
}

check_package_installed() {
    local pkg="$1"
    case "$PKG_MANAGER" in
        apt) dpkg -s "$pkg" &>/dev/null ;;
        dnf|yum) rpm -q "$pkg" &>/dev/null ;;
        zypper) zypper se -i "$pkg" | grep -qw "$pkg" ;;
        pacman) pacman -Qi "$pkg" &>/dev/null ;;
        *) return 1 ;;
    esac
}

check_updates_available() {
    case "$PKG_MANAGER" in
        apt) apt list --upgradable 2>/dev/null | grep -v "Listing" | wc -l ;;
        dnf|yum) dnf check-update 2>/dev/null | grep -E '^[a-zA-Z0-9]' | wc -l ;;
        zypper) zypper list-updates | grep -c "^v " ;;
        pacman) checkupdates 2>/dev/null | wc -l ;;
        *) echo 0 ;;
    esac
}

check_feature_enabled() {
    local feature="$1"
    case "$feature" in
        firewalld) systemctl is-active firewalld &>/dev/null ;;
        ufw) ufw status | grep -q "Status: active" ;;
        fail2ban) systemctl is-active fail2ban &>/dev/null ;;
        auditd) systemctl is-active auditd &>/dev/null ;;
        selinux) sestatus 2>/dev/null | grep -q "enabled" ;;
        apparmor) aa-status &>/dev/null ;;
        aide) [[ -f /etc/aide/aide.conf || -f /etc/aide.conf ]] ;;
        *) return 1 ;;
    esac
}

run_hardening_check() {
    echo -e "\n${YELLOW}========== HARDENING CHECK ==========${NC}"

    if command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
        echo -e "${GREEN}    📦 Detected APT-based system (Debian/Ubuntu)"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
        echo -e "${GREEN}    📦 Detected DNF-based system (Fedora/RHEL/CentOS)"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
        echo -e "${GREEN}    📦 Detected YUM-based system (Legacy RHEL)"
    elif command -v zypper &>/dev/null; then
        PKG_MANAGER="zypper"
        echo -e "${GREEN}    📦 Detected openSUSE (Zypper)"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
        echo -e "${GREEN}    📦 Detected Arch-based system"
    else
        echo -e "${FGR}${YELLOW}    ⚠️ Unknown package manager. Skipping checks."
        return
    fi

    echo -e "\n${LIGHT_MAGENTA}    🔎 Security Update & Hardening Recommendations"

    updates=$(check_updates_available)
    if [[ "$updates" -gt 0 ]]; then
        echo -e "${RED}       🔄 ${updates} packages can be updated"
    else
        echo -e "${GREEN}       ✅ System is up to date"
    fi

    echo -e "${LIGHT_MAGENTA}       🔒 Evaluating hardening tools:"
    for pkg in fail2ban auditd aide; do
        if check_package_installed "$pkg"; then
            if check_feature_enabled "$pkg"; then
                echo -e "${GREEN}       ✅ $pkg is installed and active"
            else
                echo -e "${RED}       ⚠️  $pkg is installed but not active${NC}"
            fi
        else
            echo -e "${BLUE}       🔧 Suggest installing $pkg${NC}"
        fi
    done
    
    firewall_check
    
    if [[ "$PKG_MANAGER" == "apt" ]]; then

        [[ -d /etc/apparmor.d ]] && check_feature_enabled "apparmor" || echo -e "${BLUE}       🔧 Suggest enabling AppArmor (if supported)${NC}"

    elif [[ "$PKG_MANAGER" =~ dnf|yum ]]; then
        if check_package_installed "firewalld"; then
            check_feature_enabled "firewalld" || echo -e "${RED}       ⚠️  firewalld installed but inactive${NC}"
        else
            echo -e "${BLUE       🔧 Suggest installing}firewalld${NC}"
        fi

        check_feature_enabled "selinux" || echo -e "       🔧 Suggest enabling ${BLUE}SELinux${NC} (if supported)"
    fi

    echo -e "\n${LIGHT_MAGENTA}       🔐 SSH Root Login Check:${NC}"
    if grep -Eqi '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config; then
        echo -e "${GREEN}       ✅ PermitRootLogin is set to 'no'"
    else
        echo -e "${RED}       ❌ PermitRootLogin is NOT set to 'no' or is commented"
        echo -e "       ${BLUE}Recommendation: Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
    fi

    echo -e "\n${LIGHT_MAGENTA}       🔑 PAM Password Policy:${NC}"
    if grep -qE 'pam_(pwquality|cracklib)' /etc/pam.d/common-password 2>/dev/null; then
        echo -e "${GREEN}       ✅ PAM password complexity is enforced"
    else
        echo -e "${RED}       ❌ PAM complexity module not found in common-password"
        echo -e "       ${BLUE}Recommendation: Configure pam_pwquality or pam_cracklib in /etc/pam.d/common-password"
    fi

    echo -e "\n${LIGHT_MAGENTA}       🛡️ Intrusion Detection Tools:${NC}"
    if command -v aide &>/dev/null || systemctl is-active --quiet ossec; then
        echo -e "${GREEN}       ✅ Intrusion detection system installed (AIDE or OSSEC)"
    else
        echo -e "${RED}       ❌ No IDS detected"
        echo -e "       ${BLUE}Recommendation: Install AIDE or OSSEC for host-based intrusion detection"
    fi

    echo -e "\n${LIGHT_MAGENTA}       📋 Audit Logging (auditd):${NC}"
    if systemctl is-active --quiet auditd; then
        echo -e "${GREEN}       ✅ auditd is active"
    else
        echo -e "${RED}       ❌ auditd not running"
        echo -e "       ${BLUE}Recommendation: Install and enable auditd to monitor system events"
    fi

    echo -e "\n${LIGHT_MAGENTA}       🛠️ Automatic Security Updates:${NC}"
    auto_upd_installed=0
    case $(get_os | tr '[:upper:]' '[:lower:]') in
        *ubuntu*|*debian*)
            if dpkg -l | grep -q unattended-upgrades; then
                auto_upd_installed=1
            fi
            ;;
        *centos*|*rocky*|*rhel*)
            if rpm -q dnf-automatic &>/dev/null; then
                auto_upd_installed=1
            fi
            ;;
        *arch*)
            echo -e "${YELLOW}       ⚠️ Arch-based systems typically do not support automatic updates"
            ;;
    esac

    if [[ "$auto_upd_installed" -eq 1 ]]; then
        echo -e "${GREEN}       ✅ Automatic security update service installed"
    else
        echo -e "${RED}       ❌ No automatic update system detected"
        echo -e "       ${BLUE}Recommendation:} Install 'unattended-upgrades' (Debian/Ubuntu) or 'dnf-automatic' (RHEL/Fedora)"
    fi
    echo
    echo -e "${YELLOW}========== END HARDENING REPORT ==========${NC}"
}


if [[ $EUID -ne 0 ]]; then
  echo -e "${YELLOW}    Warning:${NC} Some checks (firewall, SUID binaries, etc.) require root privileges to report accurately."
fi

####################
#  MAIN DISPLAY
####################
if [ "$SHOW_ART" -eq 1 ]; then
  clear
  echo -e "\n\n${YELLOW}             ⚙️    LinFo   ⚙️${NC}"
  echo -e "${LIGHT_MAGENTA}      🕵🔎 Powered by  Kaotick Jay 👽          \n${NC}"
fi

kernel_version=$(uname -r)
kernel_arch=$(uname -m)
logged_in_users=$(who | wc -l)

echo -e "${GREEN}    🌍 OS:${LIGHT_CYAN} $(get_os)${NC}"
echo -e "${GREEN}    🏠 Host:${LIGHT_CYAN} $(hostname)${NC}"
echo -e "${GREEN}    🐧 Kernel:${LIGHT_CYAN} ${kernel_version} (${kernel_arch})${NC}"
echo -e "${GREEN}    ⏲️  Uptime:${LIGHT_CYAN} $(uptime -p)${NC}"
echo -e "${GREEN}    📦 Packages:${LIGHT_CYAN} $(get_packages)${NC}"
echo -e "${GREEN}    🖥️  DE:${LIGHT_CYAN} $(get_de)${NC}"
echo -e "${GREEN}    🎨 Resolution:${LIGHT_CYAN} $(get_resolution)${NC}"
echo -e "${GREEN}    💻 Terminal:${LIGHT_CYAN} $TERM${NC}"
echo -e "${GREEN}    🔨 Shell:${LIGHT_CYAN} $(basename "$SHELL") $( $SHELL --version 2>/dev/null | head -n1 )${NC}"
echo -e "${GREEN}    ⚡️ CPU:${LIGHT_CYAN} $(get_cpu)${NC}"
echo -e "${GREEN}    🎮 GPU:${LIGHT_CYAN} $(get_gpu)${NC}"
echo -e "${GREEN}    🧠 Memory:${LIGHT_CYAN} $(get_memory)${NC}"
echo -e "${GREEN}    💾 Disk Usage:${LIGHT_CYAN} $(get_disk)${NC}\n"
echo -e "${GREEN}    📡 Virtualization: ${NC}$(systemd-detect-virt 2>/dev/null || echo "Unknown")"
echo -e "${GREEN}    📂 Mounted Partitions:${LIGHT_CYAN}"
lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT | grep -v "loop" | grep -v "sr0" | awk '{print "    " $0}'

echo
echo -e "${LIGHT_MAGENTA}         User Info"
echo -e "${GREEN}    👥 Logged-in users:${LIGHT_CYAN} $logged_in_users${NC}"
echo -e "${GREEN}    📜 Last Logins:${BLUE}"
last -n 3 | head -n 3 | awk '{print "    " $1, $5, $6, $7, $8}'
echo -e "${GREEN}    ⚠️  Users with UID 0:${RED} $(awk -F: '$3 == 0 {print $1}' /etc/passwd | xargs)"
echo -e "${GREEN}    🛡️  Sudoers Group Members:${YELLOW} $(getent group sudo | cut -d: -f4)"


if [ "$SKIP_IP" -eq 0 ]; then
  echo -e "${GREEN}    🌐 Network Interfaces and IPs:${NC}\n"
  for iface in $(get_interfaces); do
    ip=$(get_interface_ip "$iface")
    mac=$(ip link show "$iface" | awk '/link\/ether/ {print $2}')
    echo -e "      ${GREEN}🔗 $iface: ${LIGHT_CYAN}IP: $ip | MAC: $mac${NC}"
  done
fi
echo
echo -e "${GREEN}    🚪 Default Gateway:${LIGHT_CYAN} $(ip route | grep default | awk '{print $3}')"
echo -e "${GREEN}    🧭 DNS Servers:${LIGHT_CYAN}"
grep "nameserver" /etc/resolv.conf | awk '{print "    " $2}'
echo
# Open Ports (if available)
if command -v ss &>/dev/null; then
    echo -e "${GREEN}    🔓 Open TCP/UDP Ports (Listening):${LIGHT_CYAN}"
    ss -tuln | grep LISTEN | awk '{print "    " $0}'
elif command -v netstat &>/dev/null; then
    echo -e "${GREEN}    🔓 Open TCP/UDP Ports (Listening):${LIGHT_CYAN}"
    netstat -tuln | grep LISTEN | awk '{print "    " $0}'
fi


####################
#  SECURITY MODES
####################
run_scan_report() {
    echo -e "${YELLOW}    ####################${NC}"
    echo -e "${YELLOW}    #  SECURITY REPORT  ${NC}"
    echo -e "${YELLOW}    ####################${NC}"

    echo "----------------------------"

    # Root access check
    if [[ $(whoami) == "root" ]]; then
        echo -e "    🔥 Root access: ${GREEN}YES${NC}"
    else
        echo -e "    🔥 Root access: ${RED}NO${NC}"
    fi

    # Firewall status (requires root)
    if [[ $EUID -eq 0 ]]; then
        if systemctl is-active ufw &>/dev/null || iptables -L -n &>/dev/null; then
            echo -e "    🧱 Firewall active: ${GREEN}YES${NC}"
        else
            echo -e "    🧱 Firewall active: ${RED}NO${NC}"
        fi
    else
        echo -e "    🧱 Firewall active: ${YELLOW}Insufficient permissions to check${NC}"
    fi

    # SSH daemon running
    if pgrep -x sshd &>/dev/null; then
        echo -e "    🔐 SSH running: ${GREEN}YES${NC}"
    else
        echo -e "    🔐 SSH running: ${RED}NO${NC}"
    fi

    # SELinux or AppArmor status
    if command -v getenforce &>/dev/null; then
        echo -e "    🧬 SELinux: ${GREEN}$(getenforce)${NC}"
    elif [ -d /sys/module/apparmor ]; then
        echo -e "    🧬 AppArmor: ${GREEN}Enabled${NC}"
    else
        echo -e "    🧬 SELinux/AppArmor: ${RED}Not detected${NC}"
    fi
    get_kernel_hardening

    # Kernel exploitability with bc and fallback
    kernel_version=$(uname -r | cut -d. -f1-2)

    if command -v bc &>/dev/null; then
        is_less=$(echo "$kernel_version < 5.15" | bc -l)
        if [[ "$is_less" -eq 1 ]]; then
            echo -e "    🧪 Kernel Exploitable: ${YELLOW}POSSIBLY (kernel < 5.15)${NC}"
        else
            echo -e "    🧪 Kernel Exploitable: ${GREEN}Unlikely (>= 5.15)${NC}"
        fi
    else
        kernel_major=$(echo "$kernel_version" | cut -d. -f1)
        kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
        
        if (( kernel_major < 5 )) || { (( kernel_major == 5 )) && (( kernel_minor < 15 )); }; then
            echo -e "    🧪 Kernel Exploitable: ${YELLOW}POSSIBLY (kernel < 5.15)${NC}"
        else
            echo -e "    🧪 Kernel Exploitable: ${GREEN}Unlikely (>= 5.15)${NC}"
        fi
    fi

    # Count of SUID binaries in standard paths
    suid_count=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm -4000 -type f 2>/dev/null | wc -l)
    echo -e "    📜 SUID Binaries (standard paths): ${LIGHT_CYAN}${suid_count} found${NC}"

    # Suspicious SUID binaries outside standard paths
    echo -e "    📜 Suspicious SUID binaries outside standard paths:"
    find / -mount \( -path /bin -o -path /sbin -o -path /usr/bin -o -path /usr/sbin -o -path /usr/local/bin -o -path /usr/local/sbin -o -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -perm -4000 -type f -print 2>/dev/null | while read -r f; do
        echo -e "       ${YELLOW}$f${NC}"
    done

    # /etc/shadow permissions
    shadow_perms=$(stat -c '%a' /etc/shadow 2>/dev/null || echo "N/A")
    echo -e "    🔒 /etc/shadow permissions: ${LIGHT_CYAN}${shadow_perms}${NC}"

    # Number of crontab directories
    crons=$(ls /etc/cron.* 2>/dev/null | wc -l)
    echo -e "    👁️  Crontabs detected: ${LIGHT_CYAN}${crons} found${NC}"

    # World-writable directories count
    writable_dirs=$(find /tmp /var /home /usr/local /opt -type d -perm -0002 2>/dev/null | wc -l)
    echo -e "    📁 World-writable dirs: ${LIGHT_CYAN}${writable_dirs}${NC}"

    # World-writable files count
    writable_files=$(find /tmp /var /home /usr/local /opt -type f -perm -0002 2>/dev/null | wc -l)
    echo -e "    📄 World-writable files: ${LIGHT_CYAN}${writable_files}${NC}"

    # Listening TCP ports
    echo -e "    🌐 Listening TCP ports:"
    ss -tuln 2>/dev/null | awk 'NR>1 {print "       " $5}' || echo "       Unable to run ss"

    # Extra UID 0 users check
    extra_root_users=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
    if [[ -n "$extra_root_users" ]]; then
        echo -e "    ⚠️ Extra UID 0 users:\n       ${RED}$extra_root_users${NC}"
    else
        echo -e "    ✅ No extra UID 0 users detected"
    fi

    # Writable NFS/Samba shares
    echo -e "    📁 Writable NFS/Samba Shares:"
    if command -v showmount &>/dev/null; then
        showmount -e 2>/dev/null | grep -E "^\S+\s+/\S+" | while read -r share; do
            share_path=$(echo "$share" | awk '{print $2}')
            if [ -w "$share_path" ]; then
                echo -e "       ${YELLOW}$share${NC}"
            fi
        done
    else
        echo -e "       ${RED}showmount not found${NC}"
    fi

    # PATH dangers: current directory and writable entries
    echo -e "    💣 PATH DANGER:"
    IFS=':' read -ra pths <<< "$PATH"
    for p in "${pths[@]}"; do
        if [[ "$p" == "." ]]; then
            echo -e "       ${RED}🔴 PATH includes current directory (.)${NC}"
        fi
        if [[ -w "$p" ]]; then
            echo -e "       ${YELLOW}⚠️  Writable PATH entry: $p${NC}"
        fi
    done

    # Unusual background processes (netcat, python sockets, dev/tcp)
    echo -e "    🧠 Unusual background processes:"
    ps aux | grep -Ei 'nc|ncat|python.*socket|perl.*socket|bash.*dev/tcp' | grep -v grep | while read -r line; do
        echo -e "       ${YELLOW}$line${NC}"
    done

    # Unsigned kernel modules
    echo -e "    🧬 Unsigned Kernel Modules:"
    for mod in $(lsmod | awk 'NR>1 {print $1}'); do
        if ! modinfo "$mod" 2>/dev/null | grep -q 'signature'; then
            echo -e "       ${RED}$mod (unsigned)${NC}"
        fi
    done

# Suspicious environment variables
echo -e "    🧪 Suspicious env variables:"

suspicious_found=0

while IFS='=' read -r key value; do
    case "$key" in
        LD_PRELOAD|LD_LIBRARY_PATH)
            echo -e "       ${RED}[Injection]${NC} ${YELLOW}$key${NC}=${LIGHT_CYAN}$value${NC}"
            suspicious_found=1
            ;;
        PATH)
            # Detect malformed paths (leading/trailing colons or ::)
            if [[ "$value" =~ (^:|:$|::) ]]; then
                echo -e "       ${RED}[Pathing]${NC} ${YELLOW}$key${NC}=${LIGHT_CYAN}$value${NC}"
                suspicious_found=1
            fi

            IFS=':' read -ra path_parts <<< "$value"
            for p in "${path_parts[@]}"; do
                # Skip empty elements
                [[ -z "$p" ]] && continue

                note=""
                if [[ "$p" == "." ]]; then
                    note="${RED}← current directory (bad)${NC}"
                    suspicious_found=1
                elif [[ "$p" =~ ^/tmp|^/dev/shm|^/var/tmp ]]; then
                    note="${YELLOW}← temp dir (dangerous)${NC}"
                    suspicious_found=1
                elif [[ ! -d "$p" ]]; then
                    note="${RED}← non-existent${NC}"
                    suspicious_found=1
                elif [[ -w "$p" ]]; then
                    perms=$(stat -c '%A' "$p" 2>/dev/null)
                    if [[ "$perms" =~ ^d..w....w. ]]; then
                        note="${RED}← world-writable ($perms)${NC}"
                    else
                        note="${YELLOW}← writable by user ($perms)${NC}"
                    fi
                    suspicious_found=1
                fi

                if [[ -n "$note" ]]; then
                    echo -e "          ➥ ${LIGHT_CYAN}$p${NC} $note"
                fi
            done
            ;;
        PYTHONPATH|PERL5LIB|RUBYLIB|NODE_PATH|GEM_PATH)
            echo -e "       ${RED}[LangHijack]${NC} ${YELLOW}$key${NC}=${LIGHT_CYAN}$value${NC}"
            suspicious_found=1

            # Check if value contains temp or user-writable paths
            IFS=':' read -ra hijack_paths <<< "$value"
            for path in "${hijack_paths[@]}"; do
                [[ -z "$path" ]] && continue

                if [[ "$path" =~ ^/tmp|^/var/tmp|^/dev/shm ]]; then
                    echo -e "          ➥ ${LIGHT_CYAN}$path${NC} ${RED}← temp directory${NC}"
                elif [[ ! -d "$path" ]]; then
                    echo -e "          ➥ ${LIGHT_CYAN}$path${NC} ${RED}← non-existent${NC}"
                elif [[ -w "$path" ]]; then
                    perms=$(stat -c '%A' "$path" 2>/dev/null)
                    echo -e "          ➥ ${LIGHT_CYAN}$path${NC} ${YELLOW}← writable ($perms)${NC}"
                fi
            done
            ;;
    esac
done < <(env)

if [[ "$suspicious_found" -eq 0 ]]; then
    echo -e "       None detected"
fi

    echo "----------------------------"
}

####################
#  LOOT GATHERING
####################

run_loot_gather() {
    echo -e "${YELLOW}    ####################${NC}"
    echo -e "${YELLOW}    #    LOOT REPORT   ${NC}"
    echo -e "${YELLOW}    ####################${NC}"
    echo "----------------------------"

    # Potential C2 staging directories (world-writable temp dirs)
    echo -e "    ${LIGHT_MAGENTA}📂 Potential C2 staging dirs:${NC}"
    find /tmp /var/tmp /dev/shm -type d -perm -0002 2>/dev/null | while read -r dir; do
        echo -e "       ${YELLOW}💾 $dir${NC}"
    done

    # Mounted filesystems excluding common virtual filesystems
    echo -e "    ${LIGHT_MAGENTA}🧬 Mounted filesystems (targetable):}"
    mount | grep -Ev 'proc|sysfs|tmpfs|devtmpfs' | awk '{print "       "$3, "on", $1}'

    # User cron jobs (non-commented lines)
    echo -e "    ${LIGHT_MAGENTA}🔍 Interesting user cron jobs:${NC}"
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -u "    ${YELLOW}$user" -l 2>/dev/null | grep -vE '^\s*#|^\s*$' && echo -e "      ➥ $user${NC}"
    done

    # Writable binaries in user's PATH
    echo -e "    ${LIGHT_MAGENTA}⚙️ PATH writable binaries:${NC}"
    IFS=':' read -ra pths <<< "$PATH"
    for cmd_dir in "${pths[@]}"; do
        find "$cmd_dir" -maxdepth 1 -type f -writable 2>/dev/null | while read -r file; do
            echo -e "       ${YELLOW}$file${NC}"
        done
    done

    # Users with last login info
    echo -e "    ${LIGHT_MAGENTA}👤 Users and last login:${NC}"
    echo -e "${YELLOW}       $(who | awk '{print $1, $3, $4}')"

    # SSH authorized_keys files
    echo -e "    ${LIGHT_MAGENTA}🔑 SSH Authorized Keys:${NC}"
    find /home /root -name authorized_keys 2>/dev/null | while read -r keyfile; do
        echo -e "       ${YELLOW}$keyfile${NC}"
    done

    # Hidden files and directories in /tmp and /var/tmp
    echo -e "    ${LIGHT_MAGENTA}🕵️ Hidden files and dirs in /tmp and /var/tmp:${NC}"
    find /tmp /var/tmp -name ".*" \( -type f -o -type d \) 2>/dev/null | while read -r hidden; do
        echo -e "       ${YELLOW}$hidden${NC}"
    done

    # Cron jobs with suspicious commands (paths commonly used for payloads)
    echo -e "    ${LIGHT_MAGENTA}⏰ Cron jobs with potentially suspicious commands:${NC}"
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -u "    ${YELLOW}$user" -l 2>/dev/null | grep -vE '^\s*#|^\s*$' | grep -E '/tmp|/var/tmp|/dev/shm|/home' && echo -e "      ➥ $user${NC}"
    done

    # Last 10 commands from user histories
    echo -e "    ${LIGHT_MAGENTA}📜 Last 10 commands from user histories:${NC}"
    for user_home in /home/*; do
        histfile="$user_home/.bash_history"
        if [ -f "$histfile" ]; then
            echo -e "${YELLOW}      ➥ $(basename "$user_home"):"
            tail -n 10 "$histfile" | sed 's/^/         /'
        fi
    done

    # SUID binaries with detailed listing
    echo -e "    ${LIGHT_MAGENTA}📜 SUID binaries with details:${YELLOW}"
    find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm -4000 -type f 2>/dev/null | xargs -d '\n' ls -lh

    # Suspicious shell startup files (look for common backdoor/exec keywords)
    echo -e "${LIGHT_MAGENTA}    🔍 Suspicious shell startup files:"
    find /home /root -type f \( -name ".bashrc" -o -name ".profile" -o -name ".zshrc" \) 2>/dev/null | while read -r file; do
        if grep -Eq 'curl|wget|nc|ncat|/dev/tcp|base64|eval|python|perl' "$file"; then
            echo -e "      ➥ ${YELLOW}$file${NC}"
        fi
    done

    # Recently modified temp binaries (within last 2 days)
    echo -e "${LIGHT_MAGENTA}    🧪 Recently modified temp binaries:"
    find /tmp /var/tmp /dev/shm -type f -executable -mtime -2 2>/dev/null | while read -r f; do
        echo -e "       ${RED}$f${NC}"
    done

    # Recently modified SUID binaries (within last 7 days)
    echo -e "${LIGHT_MAGENTA}    🔐 Recently modified SUID binaries:"
	find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm -4000 -type f -mtime -7 2>/dev/null | while read -r bin; do
		echo -e "       ${YELLOW}$bin"
	done

    echo -e "    📁 ${LIGHT_MAGENTA}Recent files modified in /home:${NC}"
    find /home -type f -mtime -5 2>/dev/null | head -n 10 | while read -r file; do
        echo -e "       ${YELLOW}$file${NC}"
    done

    echo -e "\n    🔍 ${LIGHT_MAGENTA}Hidden files in /home and /root:${NC}"
    find /home /root -type f -name ".*" 2>/dev/null | head -n 10 | while read -r hidden; do
        echo -e "       ${YELLOW}$hidden${NC}"
    done

    echo -e "\n    💬 ${LIGHT_MAGENTA}Bash history snippets (users):${NC}"
    for userdir in /home/* /root; do
        histfile="$userdir/.bash_history"
        if [[ -f "$histfile" ]]; then
            echo -e "       🧠 ${YELLOW}${histfile}"
            tail -n 5 "    $histfile" | sed "s/^/          /" | sed "s/$/${NC}/"
        fi
    done

    echo -e "\n    🔓 ${LIGHT_MAGENTA}SSH Keys:${NC}"
    find /home /root -name "id_rsa" -o -name "authorized_keys" 2>/dev/null | while read -r keyfile; do
        echo -e "       ${YELLOW}$keyfile${NC}"
    done

    echo -e "\n    🔐 ${LIGHT_MAGENTA}Saved passwords or creds:${NC}"
    grep -ri 'password\|passwd\|token\|apikey' /home /root /var/www 2>/dev/null | head -n 10 | while read -r line; do
        echo -e "       ${YELLOW}$line${NC}"
    done

    echo -e "\n    📄 ${LIGHT_MAGENTA}Interesting config files:${NC}"
    find /etc -type f \( -name "*.conf" -o -name "*.cfg" \) 2>/dev/null | head -n 10 | while read -r cfg; do
        echo -e "       ${YELLOW}$cfg${NC}"
    done

    echo -e "\n    🗄️  ${LIGHT_MAGENTA}World-readable shadow or passwd files:${NC}"
    find /etc -name "shadow" -o -name "passwd" -perm -004 2>/dev/null | while read -r worldfile; do
        echo -e "       ${YELLOW}$worldfile${NC}"
    done

    echo -e "\n    💾 ${LIGHT_MAGENTA}Mounted external storage:${NC}"
    lsblk -o NAME,MOUNTPOINT,FSTYPE,SIZE | grep -i -E "media|mnt" | while read -r mount; do
        echo -e "       ${YELLOW}$mount${NC}"
    done
    echo
    echo
    echo "${GREEN}####################"
    echo "#  END LOOT REPORT     "
    echo "####################${NC}"
}

if [[ "$RUN_SCAN" -eq 1 && "$RUN_LOOT" -eq 1 && "$RUN_HARDENING" -eq 1 ]]; then
    fullscan_output_handler
elif [[ "$RUN_SCAN" -eq 1 ]]; then
    scan_output_handler
    echo
elif [[ "$RUN_LOOT" -eq 1 ]]; then
    loot_output_handler
    echo
elif [[ "$RUN_HARDENING" == 1 ]]; then
    hardening_output_handler
fi
####################
#  BANNER
####################
echo
echo

if [ "$SHOW_ART" -eq 1 ]; then
for i in {1..14}; do
	echo -ne "   $(printf '🎈%.0s' $(seq 1 $i))\r"
	sleep .1
done
sleep .5
echo -ne "               ${GREEN}Report complete \n"

lines=(
"    ██▓     ██▓ ███▄    █   █████▒▒█████  "
"   ▓██▒    ▓██▒ ██ ▀█   █ ▓██   ▒▒██▒  ██▒"
"   ▒██░    ▒██▒▓██  ▀█ ██▒▒████ ░▒██░  ██▒"
"   ▒██░    ░██░▓██▒  ▐▌██▒░▓█▒  ░▒██   ██░"
"   ░██████▒░██░▒██░   ▓██░░▒█░   ░ ████▓▒░"
"   ░ ▒░▓  ░░▓  ░ ▒░   ▒ ▒  ▒ ░   ░ ▒░▒░▒░ "
"   ░ ░ ▒  ░ ▒ ░░ ░░   ░ ▒░ ░       ░ ▒ ▒░ "
"     ░ ░    ▒ ░   ░   ░ ░  ░ ░   ░ ░ ░ ▒  "
"       ░  ░ ░           ░            ░ ░  "
)
sleep .5
echo -e "$RED"
for line in "${lines[@]}"; do
  echo "$line"
  sleep 0.1
done
echo -e "$NC"

parts=(
  "      🎈🎈🎈 "
  "${LIGHT_CYAN}y"
  "${YELLOW}O"
  "${BLUE}u"
  "${LIGHT_MAGENTA}'L"
  "${RED}l"
  "${YELLOW} f"
  "${LIGHT_CYAN}L"
  "${RED}o"
  "${LIGHT_CYAN}A"
  "${YELLOW}t"
  "${GREEN} "
  "${BLUE}t"
  "${LIGHT_MAGENTA}O"
  "${GREEN}o! 🎈🎈🎈        "
  "${NC}"
)


echo -n ""
for part in "${parts[@]}"; do
  echo -ne "$part"
  sleep 0.1
done
echo  
fi

tput sgr0
