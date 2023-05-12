#!/bin/bash
# Script: LinFo v 0.1
# Author: kaotickj
# Website: https://github.com/kaotickj


####################
#  COLORS
####################
C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
YELLOW="${C}[1;33m"
BLUE="${C}[1;34m"
LIGHT_MAGENTA="${C}[1;95m"
LIGHT_CYAN="${C}[1;96m"
LG="${C}[1;37m" #LightGray
DG="${C}[1;90m" #DarkGray
NC="${C}[0m"

os=$(uname -s)
if [[ "$os" == "Linux" ]]; then
    os=$(lsb_release -sd 2>/dev/null)
elif [[ "$os" == "Darwin" ]]; then
    os=$(sw_vers -productName 2>/dev/null)
fi
kernel=$(uname -r)
host=$(hostname)
uptime=$(uptime -p)
packages=$(dpkg-query -f '${binary:Package}\n' -W 2>/dev/null | wc -l)
de=$(echo "$XDG_CURRENT_DESKTOP" | tr '[:upper:]' '[:lower:]')
resolution=$(xdpyinfo | awk '/dimensions:/ {print $2}')
terminal=$(echo "$TERM")
shell=$(basename "$SHELL")
cpu=$(lscpu | awk -F':' '/Model name/ {print $2}' | sed -e 's/^[ \t]*//' 2>/dev/null)
gpu=$(lspci | grep -i 'vga\|3d' | awk -F': ' '{print $2}' 2>/dev/null)
memory=$(grep MemTotal /proc/meminfo | awk '{print $2/1024/1024 "GB"}' 2>/dev/null)
disk=$(df -h --total 2>/dev/null | awk '/total/ {print $2 " used, " $4 " free"}')
interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo')

clear
echo
echo -e "\n\n${YELLOW}             ⚙️    LinFo   ⚙️"
echo -e "${LIGHT_MAGENTA}      🕵🔎 Powered by  KaotickJ 👽          \n" 
echo -e "${GREEN}    🌍 OS:${LIGHT_CYAN} $os"
echo -e "${GREEN}    🏠 Host:${LIGHT_CYAN} $host"
echo -e "${GREEN}    🐧 Kernel:${LIGHT_CYAN} $kernel"
echo -e "${GREEN}    ⏲️  Uptime:${LIGHT_CYAN} $uptime"
echo -e "${GREEN}    📦 Packages:${LIGHT_CYAN} $packages"
echo -e "${GREEN}    🖥️  DE:${LIGHT_CYAN} $de"
echo -e "${GREEN}    🎨 Resolution:${LIGHT_CYAN} $resolution"
echo -e "${GREEN}    💻 Terminal:${LIGHT_CYAN} $terminal"
echo -e "${GREEN}    🔨 Shell:${LIGHT_CYAN} $shell"
echo -e "${GREEN}    ⚡️ CPU:${LIGHT_CYAN} $cpu"
echo -e "${GREEN}    🎮 GPU:${LIGHT_CYAN} $gpu"
echo -e "${GREEN}    🧠 Memory:${LIGHT_CYAN} $memory"
echo -e "${GREEN}    💾 Disk Usage:${LIGHT_CYAN} $disk\n"
echo -e "${GREEN}    🌐 Interfaces:\n"
for interface in $interfaces; do
    ip=$(ip -o addr show dev $interface | awk '$3 == "inet" {print $4}')
    echo "    	${GREEN}🔗 $interface: ${LIGHT_CYAN}$ip"
done
echo
echo -e "${RED}
    ██▓     ██▓ ███▄    █   █████▒▒█████  
   ▓██▒    ▓██▒ ██ ▀█   █ ▓██   ▒▒██▒  ██▒
   ▒██░    ▒██▒▓██  ▀█ ██▒▒████ ░▒██░  ██▒
   ▒██░    ░██░▓██▒  ▐▌██▒░▓█▒  ░▒██   ██░
   ░██████▒░██░▒██░   ▓██░░▒█░   ░ ████▓▒░
   ░ ▒░▓  ░░▓  ░ ▒░   ▒ ▒  ▒ ░   ░ ▒░▒░▒░ 
   ░ ░ ▒  ░ ▒ ░░ ░░   ░ ▒░ ░       ░ ▒ ▒░ 
     ░ ░    ▒ ░   ░   ░ ░  ░ ░   ░ ░ ░ ▒  
       ░  ░ ░           ░            ░ ░  
"
echo -e "      🎈🎈🎈 ${LIGHT_CYAN}y${YELLOW}O${BLUE}u${LIGHT_MAGENTA}'L${RED}l${YELLOW} f${LIGHT_CYAN}L${RED}o${LIGHT_CYAN}A${YELLOW}t${GREEN} ${BLUE}t${LIGHT_MAGENTA}O${GREEN}o! 🎈🎈🎈        ${NC}"
tput sgr0
