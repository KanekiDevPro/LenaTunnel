#!/bin/bash

# ---------------- INSTALL DEPENDENCIES ----------------
echo "[*] Updating package list..."
sudo apt update -y

packages=(iproute2 net-tools grep awk sudo iputils-ping jq curl haproxy iptables)
for pkg in "${packages[@]}"; do
    echo "[*] Installing $pkg..."
    sudo apt install -y $pkg
    done

# ---------------- COLORS ----------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ---------------- FUNCTIONS ----------------
check_core_status() {
    ip link show | grep -q 'vxlan' && echo "Active" || echo "Inactive"
}

Lena_menu() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country')
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp')

    echo "+-------------------------------------------------------------------------+"
    cat << "EOF"
    | _                      
    || |                      
    || |     ___ _ __   __ _ 
    || |    / _ \ '_ \ / _  |
    || |___|  __/ | | | (_| |
    |\_____/\___|_| |_|\__,_|  V1.0.5 Beta |
    EOF
    echo "+-------------------------------------------------------------------------+"
    echo -e "| Telegram Channel : ${MAGENTA}@AminiDev ${NC}| Version : ${GREEN} 1.0.5 Beta ${NC} "
    echo "+-------------------------------------------------------------------------+"
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo "+-------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Please choose an option:${NC}"
    echo "+-------------------------------------------------------------------------+"
    echo -e "1- Install new tunnel"
    echo -e "2- Uninstall tunnel(s)"
    echo -e "3- Install BBR"
    echo -e "4- install cronjob"
    echo "+-------------------------------------------------------------------------+"
    echo -e "\033[0m"
}

uninstall_all_vxlan() {
    echo "[!] Deleting all VXLAN interfaces and cleaning up..."
    for i in $(ip -d link show | grep -o 'vxlan[0-9]\+'); do
        ip link del $i 2>/dev/null
    done
    rm -f /usr/local/bin/vxlan_bridge*.sh /etc/ping_vxlan.sh
    systemctl disable --now vxlan-tunnel*.service 2>/dev/null
    rm -f /etc/systemd/system/vxlan-tunnel*.service
    systemctl daemon-reload
    systemctl reset-failed
    systemctl daemon-reexec
    systemctl daemon-reload
    systemctl stop haproxy 2>/dev/null
    systemctl disable haproxy 2>/dev/null
    apt remove -y haproxy 2>/dev/null
    apt purge -y haproxy 2>/dev/null
    apt autoremove -y 2>/dev/null
    crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' | grep -v '/etc/ping_vxlan.sh' > /tmp/cron_tmp || true
    crontab /tmp/cron_tmp
    rm /tmp/cron_tmp
    echo "[+] All VXLAN tunnels and related cronjobs deleted."
}

install_bbr() {
    echo "Running BBR script..."
    curl -fsSL https://raw.githubusercontent.com/MrAminiDev/NetOptix/main/scripts/bbr.sh -o /tmp/bbr.sh
    bash /tmp/bbr.sh
    rm /tmp/bbr.sh
}

install_haproxy_and_configure() {
    echo "[*] Configuring HAProxy..."
    if ! command -v haproxy >/dev/null 2>&1; then
        sudo apt update && sudo apt install -y haproxy
    fi

    sudo mkdir -p /etc/haproxy
    local CONFIG_FILE="/etc/haproxy/haproxy.cfg"
    local BACKUP_FILE="/etc/haproxy/haproxy.cfg.bak"
    [ -f "$CONFIG_FILE" ] && cp "$CONFIG_FILE" "$BACKUP_FILE"

    cat <<EOL > "$CONFIG_FILE"
global
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn 4096

defaults
    mode    tcp
    option  dontlognull
    timeout connect 5000ms
    timeout client  50000ms
    timeout server  50000ms
    retries 3
    option  tcpka
EOL

    read -p "Enter ports (comma-separated): " user_ports
    local local_ip=$(hostname -I | awk '{print $1}')
    IFS=',' read -ra ports <<< "$user_ports"
    for port in "${ports[@]}"; do
        cat <<EOL >> "$CONFIG_FILE"

frontend frontend_$port
    bind *:$port
    default_backend backend_$port
    option tcpka

backend backend_$port
    option tcpka
    server server1 $local_ip:$port check maxconn 2048
EOL
    done

    if haproxy -c -f "$CONFIG_FILE"; then
        systemctl restart haproxy
        systemctl enable haproxy
        echo -e "${GREEN}HAProxy configured and restarted successfully.${NC}"
    else
        echo -e "${YELLOW}Warning: HAProxy configuration is invalid!${NC}"
    fi
}

# ---------------- MAIN ----------------
while true; do
    Lena_menu
    read -p "Enter your choice [1-4]: " main_action
    case $main_action in
        1) break ;;
        2) uninstall_all_vxlan; read -p "Press Enter to return to menu..." ;;
        3) install_bbr; read -p "Press Enter to return to menu..." ;;
        4)
            while true; do
                read -p "How many hours between each restart? (1-24): " cron_hours
                if [[ $cron_hours =~ ^[0-9]+$ ]] && (( cron_hours >= 1 && cron_hours <= 24 )); then
                    break
                else
                    echo "Invalid input. Please enter a number between 1 and 24."
                fi
            done
            crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' > /tmp/cron_tmp || true
            echo "0 */$cron_hours * * * systemctl restart haproxy >/dev/null 2>&1" >> /tmp/cron_tmp
            echo "0 */$cron_hours * * * systemctl restart vxlan-tunnel-* >/dev/null 2>&1" >> /tmp/cron_tmp
            crontab /tmp/cron_tmp
            rm /tmp/cron_tmp
            echo -e "${GREEN}Cronjob set successfully.${NC}"
            read -p "Press Enter to return to menu..." ;;
        *) echo "[x] Invalid option. Try again."; sleep 1 ;;
    esac
done

# ---------------- ROLE SELECTOR ----------------
echo "Choose server role:"
echo "1- Iran"
echo "2- Kharej"
read -p "Enter choice (1/2): " role_choice

if [[ "$role_choice" == "1" ]]; then
    read -p "How many foreign servers to connect? " foreign_count
    declare -a KHAREJ_IPS
    declare -a DSTPORTS

    for ((i = 0; i < foreign_count; i++)); do
        read -p "Enter Kharej IP #$((i+1)): " KHAREJ_IPS[i]
        while true; do
            read -p "Enter Tunnel port for Kharej #$((i+1)) (1 ~ 64435): " port
            if [[ $port =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 64435 )); then
                DSTPORTS[i]=$port
                break
            else
                echo "Invalid port. Try again."
            fi
        done
    done

    read -p "Enter IRAN server's IP: " IRAN_IP

    while true; do
        read -p "Should port forwarding be done automatically? (HAProxy) [1-yes, 2-no]: " haproxy_choice
        if [[ "$haproxy_choice" == "1" || "$haproxy_choice" == "2" ]]; then
            break
        else
            echo "Please enter 1 (yes) or 2 (no)."
        fi
    done
    if [[ "$haproxy_choice" == "1" ]]; then
        install_haproxy_and_configure
    fi

    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    ipv4_local=$(hostname -I | awk '{print $1}')

    for ((i = 0; i < foreign_count; i++)); do
        VNI=$((88 + i))
        VXLAN_IF="vxlan${VNI}"
        VXLAN_IP="30.0.0.$((i+1))/24"
        REMOTE_IP="${KHAREJ_IPS[i]}"
        DSTPORT="${DSTPORTS[i]}"

        echo "[+] Creating VXLAN interface $VXLAN_IF to $REMOTE_IP on port $DSTPORT"
        ip link add $VXLAN_IF type vxlan id $VNI local $ipv4_local remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
        ip addr add $VXLAN_IP dev $VXLAN_IF
        ip link set $VXLAN_IF up

        iptables -I INPUT 1 -p udp --dport $DSTPORT -j ACCEPT
        iptables -I INPUT 1 -s $REMOTE_IP -j ACCEPT
        iptables -I INPUT 1 -s ${VXLAN_IP%/*} -j ACCEPT

        BRIDGE_SCRIPT="/usr/local/bin/vxlan_bridge_$VNI.sh"
        SERVICE_FILE="/etc/systemd/system/vxlan-tunnel-$VNI.service"

        cat <<EOF > "$BRIDGE_SCRIPT"
#!/bin/bash
ip link add $VXLAN_IF type vxlan id $VNI local $ipv4_local remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
ip addr add $VXLAN_IP dev $VXLAN_IF
ip link set $VXLAN_IF up
( while true; do ping -c 1 $REMOTE_IP >/dev/null 2>&1; sleep 30; done ) &
EOF

        chmod +x "$BRIDGE_SCRIPT"

        cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=VXLAN Tunnel $VXLAN_IF
After=network.target

[Service]
ExecStart=$BRIDGE_SCRIPT
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

        chmod 644 "$SERVICE_FILE"
        systemctl daemon-reload
        systemctl enable vxlan-tunnel-$VNI.service
        systemctl start vxlan-tunnel-$VNI.service

        echo -e "${GREEN}[✓] VXLAN $VXLAN_IF setup complete.${NC}"
    done

    echo -e "${GREEN}[✓] All VXLAN tunnels set up successfully.${NC}"

elif [[ "$role_choice" == "2" ]]; then
    read -p "Enter IRAN IP: " IRAN_IP
    read -p "Enter Kharej IP: " KHAREJ_IP
    while true; do
        read -p "Tunnel port (1 ~ 64435): " DSTPORT
        if [[ $DSTPORT =~ ^[0-9]+$ ]] && (( DSTPORT >= 1 && DSTPORT <= 64435 )); then
            break
        else
            echo "Invalid port. Try again."
        fi
    done
    echo -e "####################################"
    echo -e "# Your IPv4 : 30.0.0.2              #"
    echo -e "####################################"

    VNI=88
    VXLAN_IF="vxlan${VNI}"
    VXLAN_IP="30.0.0.2/24"
    REMOTE_IP=$IRAN_IP
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    ipv4_local=$(hostname -I | awk '{print $1}')

    ip link add $VXLAN_IF type vxlan id $VNI local $ipv4_local remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
    ip addr add $VXLAN_IP dev $VXLAN_IF
    ip link set $VXLAN_IF up

    iptables -I INPUT 1 -p udp --dport $DSTPORT -j ACCEPT
    iptables -I INPUT 1 -s $REMOTE_IP -j ACCEPT
    iptables -I INPUT 1 -s ${VXLAN_IP%/*} -j ACCEPT

    cat <<EOF > /usr/local/bin/vxlan_bridge.sh
#!/bin/bash
ip link add $VXLAN_IF type vxlan id $VNI local $ipv4_local remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
ip addr add $VXLAN_IP dev $VXLAN_IF
ip link set $VXLAN_IF up
( while true; do ping -c 1 $REMOTE_IP >/dev/null 2>&1; sleep 30; done ) &
EOF

    chmod +x /usr/local/bin/vxlan_bridge.sh

    cat <<EOF > /etc/systemd/system/vxlan-tunnel.service
[Unit]
Description=VXLAN Tunnel Interface
After=network.target

[Service]
ExecStart=/usr/local/bin/vxlan_bridge.sh
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 /etc/systemd/system/vxlan-tunnel.service
    systemctl daemon-reexec
    systemctl daemon-reload
    systemctl enable vxlan-tunnel.service
    systemctl start vxlan-tunnel.service

    echo -e "\n${GREEN}[✓] VXLAN tunnel service enabled to run on boot.${NC}"
    echo "[✓] VXLAN tunnel setup completed successfully."
else
    echo "[x] Invalid role selected."
    exit 1
fi
