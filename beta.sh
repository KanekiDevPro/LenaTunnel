#!/bin/bash

# ---------------- INSTALL DEPENDENCIES ----------------
echo "[*] Updating package list..."
sudo apt update -y

echo "[*] Installing iproute2..."
sudo apt install -y iproute2

echo "[*] Installing net-tools..."
sudo apt install -y net-tools

echo "[*] Installing grep..."
sudo apt install -y grep

echo "[*] Installing awk..."
sudo apt install -y awk

echo "[*] Installing sudo..."
sudo apt install -y sudo

echo "[*] Installing iputils-ping..."
sudo apt install -y iputils-ping

echo "[*] Installing jq..."
sudo apt install -y jq

echo "[*] Installing curl..."
sudo apt install -y curl

echo "[*] Installing haproxy..."
sudo apt install -y haproxy

echo "[*] Installing iptables..."
sudo apt install -y iptables

# ---------------- COLORS ----------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ---------------- FUNCTIONS ----------------

check_core_status() {
    ip link show | grep -q 'vxlan' && echo "Active" || echo "Inactive"
}

main_menu() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country')
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp')

    echo "+-------------------------------------------------------------------------+"
    echo "| _                      									|"
    echo "|| |                     									|"
    echo "|| |     ___ _ __   __ _ 									|"
    echo "|| |    / _ \ '_ \ / _  |									|"
    echo "|| |___|  __/ | | | (_| |									|"
    echo "|\_____/\___|_| |_|\__,_|	V1.0.5 Beta			            |" 
    echo "+-------------------------------------------------------------------------+"    
    echo -e "| Telegram Channel : ${MAGENTA}@AminiDev ${NC}| Version : ${GREEN} 1.0.5 Beta ${NC} "
    echo "+-------------------------------------------------------------------------+"
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo "+-------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Please choose an option:${NC}"
    echo "+-------------------------------------------------------------------------+"
    echo -e "1- Install new tunnel(s)"
    echo -e "2- Uninstall tunnel(s)"
    echo -e "3- Install BBR"
    echo -e "4- Install cronjob"
    echo "+-------------------------------------------------------------------------+"
    echo -e "\033[0m"
}

uninstall_all_vxlan() {
    echo "[!] Deleting all VXLAN interfaces and cleaning up..."
    for i in $(ip -d link show | grep -o 'vxlan[0-9]\+'); do
        ip link del $i 2>/dev/null
    done
    rm -f /usr/local/bin/vxlan_bridge*.sh /etc/ping_vxlan.sh
    systemctl list-units | grep 'vxlan-tunnel-' | awk '{print $1}' | xargs -r systemctl disable --now 2>/dev/null
    rm -f /etc/systemd/system/vxlan-tunnel-*.service
    systemctl daemon-reload
    # Stop and disable HAProxy service
    systemctl stop haproxy 2>/dev/null
    systemctl disable haproxy 2>/dev/null
    # Remove HAProxy package
    apt remove -y haproxy 2>/dev/null
    apt purge -y haproxy 2>/dev/null
    apt autoremove -y 2>/dev/null
    # Remove related cronjobs
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

    # Ensure haproxy is installed
    if ! command -v haproxy >/dev/null 2>&1; then
        echo "[x] HAProxy is not installed. Installing..."
        sudo apt update && sudo apt install -y haproxy
    fi

    # Ensure config directory exists
    sudo mkdir -p /etc/haproxy

    # Default HAProxy config file
    local CONFIG_FILE="/etc/haproxy/haproxy.cfg"
    local BACKUP_FILE="/etc/haproxy/haproxy.cfg.bak"

    # Backup old config
    [ -f "$CONFIG_FILE" ] && cp "$CONFIG_FILE" "$BACKUP_FILE"

    # Write base config
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

    # Validate haproxy config
    if haproxy -c -f "$CONFIG_FILE"; then
        echo "[*] Restarting HAProxy service..."
        systemctl restart haproxy
        systemctl enable haproxy
        echo -e "${GREEN}HAProxy configured and restarted successfully.${NC}"
    else
        echo -e "${YELLOW}Warning: HAProxy configuration is invalid!${NC}"
    fi
}

# ---------------- SERVER LIST ----------------
# Format: "ROLE IRAN_IP KHAREJ_IP DSTPORT"
# ROLE: IRAN / FOREIGN
# Example:
# servers=(
#   "IRAN 10.10.10.10 20.20.20.20 5000"
#   "FOREIGN 30.30.30.30 40.40.40.40 5001"
# )
servers=()

add_server() {
    echo "Add new server tunnel configuration:"
    while true; do
        read -p "Role (1-IRAN, 2-FOREIGN): " role_choice
        if [[ "$role_choice" == "1" ]]; then
            ROLE="IRAN"
            break
        elif [[ "$role_choice" == "2" ]]; then
            ROLE="FOREIGN"
            break
        else
            echo "Invalid role. Please enter 1 or 2."
        fi
    done
    read -p "Enter IRAN IP: " IRAN_IP
    read -p "Enter FOREIGN IP: " FOREIGN_IP
    while true; do
        read -p "Tunnel port (1 ~ 64435): " DSTPORT
        if [[ $DSTPORT =~ ^[0-9]+$ ]] && (( DSTPORT >= 1 && DSTPORT <= 64435 )); then
            break
        else
            echo "Invalid port. Try again."
        fi
    done
    servers+=("$ROLE $IRAN_IP $FOREIGN_IP $DSTPORT")
    echo "[+] Server added: $ROLE $IRAN_IP $FOREIGN_IP $DSTPORT"
}

# ---------------- MULTI SERVER INSTALL ----------------
multi_vxlan_install() {
    if [ ${#servers[@]} -eq 0 ]; then
        echo "No server tunnels configured. Please add at least one."
        while true; do
            add_server
            read -p "Do you want to add another server? (y/n): " yn
            if [[ "$yn" != "y" ]]; then break; fi
        done
    fi

    # Ask for haproxy auto-forwarding
    while true; do
        read -p "Do you want automatic port forwarding with haproxy for all tunnels? [1-yes, 2-no]: " haproxy_choice
        if [[ "$haproxy_choice" == "1" || "$haproxy_choice" == "2" ]]; then
            break
        else
            echo "Please enter 1 (yes) or 2 (no)."
        fi
    done
    if [[ "$haproxy_choice" == "1" ]]; then
        # Collect all DSTPORTs for haproxy config
        ports=()
        for entry in "${servers[@]}"; do
            read -r ROLE IRAN_IP FOREIGN_IP DSTPORT <<< "$entry"
            ports+=("$DSTPORT")
        done
        user_ports=$(IFS=, ; echo "${ports[*]}")
        echo "[*] Setting up HAProxy for ports: $user_ports"
        # silent call with all ports
        echo "$user_ports" | install_haproxy_and_configure
    fi

    VNI_BASE=88
    local_ip=$(hostname -I | awk '{print $1}')
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)

    idx=0
    for entry in "${servers[@]}"; do
        read -r ROLE IRAN_IP FOREIGN_IP DSTPORT <<< "$entry"
        VNI=$((VNI_BASE + idx))
        VXLAN_IF="vxlan${VNI}"

        if [[ "$ROLE" == "IRAN" ]]; then
            VXLAN_IP="30.0.0.1/24"
            REMOTE_IP=$FOREIGN_IP
            SHOW_IP="30.0.0.1"
        else
            VXLAN_IP="30.0.0.2/24"
            REMOTE_IP=$IRAN_IP
            SHOW_IP="30.0.0.2"
        fi

        echo "----------------------------------------------"
        echo "[+] Role: $ROLE"
        echo "[+] VXLAN Interface: $VXLAN_IF"
        echo "[+] Local IP: $local_ip"
        echo "[+] Remote IP: $REMOTE_IP"
        echo "[+] Tunnel Port: $DSTPORT"
        echo -e "[+] VXLAN IP: ${GREEN}$SHOW_IP${NC}"
        echo "----------------------------------------------"

        ip link add $VXLAN_IF type vxlan id $VNI local $local_ip remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
        ip addr add $VXLAN_IP dev $VXLAN_IF
        ip link set $VXLAN_IF up

        iptables -I INPUT 1 -p udp --dport $DSTPORT -j ACCEPT
        iptables -I INPUT 1 -s $REMOTE_IP -j ACCEPT
        iptables -I INPUT 1 -s ${VXLAN_IP%/*} -j ACCEPT

        # Create systemd service for each VXLAN
        cat <<EOF > /usr/local/bin/vxlan_bridge_${VNI}.sh
#!/bin/bash
ip link add $VXLAN_IF type vxlan id $VNI local $local_ip remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
ip addr add $VXLAN_IP dev $VXLAN_IF
ip link set $VXLAN_IF up
( while true; do ping -c 1 $REMOTE_IP >/dev/null 2>&1; sleep 30; done ) &
EOF
        chmod +x /usr/local/bin/vxlan_bridge_${VNI}.sh

        cat <<EOF > /etc/systemd/system/vxlan-tunnel-${VNI}.service
[Unit]
Description=VXLAN Tunnel Interface ${VXLAN_IF}
After=network.target

[Service]
ExecStart=/usr/local/bin/vxlan_bridge_${VNI}.sh
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        chmod 644 /etc/systemd/system/vxlan-tunnel-${VNI}.service
        systemctl daemon-reload
        systemctl enable vxlan-tunnel-${VNI}.service
        systemctl start vxlan-tunnel-${VNI}.service

        echo -e "\n${GREEN}[✓] VXLAN tunnel service enabled for ${VXLAN_IF}.${NC}"
        idx=$((idx+1))
    done
    echo "[✓] Multi VXLAN tunnel setup completed successfully."
}

# ---------------- MAIN ----------------
while true; do
    main_menu
    read -p "Enter your choice [1-4]: " main_action
    case $main_action in
        1)
            multi_vxlan_install
            read -p "Press Enter to return to menu..."
            ;;
        2)
            uninstall_all_vxlan
            read -p "Press Enter to return to menu..."
            ;;
        3)
            install_bbr
            read -p "Press Enter to return to menu..."
            ;;
        4)
            while true; do
                read -p "How many hours between each restart? (1-24): " cron_hours
                if [[ $cron_hours =~ ^[0-9]+$ ]] && (( cron_hours >= 1 && cron_hours <= 24 )); then
                    break
                else
                    echo "Invalid input. Please enter a number between 1 and 24."
                fi
            done
            # Remove any previous cronjobs for these services
            crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' > /tmp/cron_tmp || true
            echo "0 */$cron_hours * * * systemctl restart haproxy >/dev/null 2>&1" >> /tmp/cron_tmp
            # Add restart for all vxlan-tunnel-* services
            for svc in $(ls /etc/systemd/system/vxlan-tunnel-*.service 2>/dev/null | xargs -n1 basename | sed 's/.service//'); do
                echo "0 */$cron_hours * * * systemctl restart $svc >/dev/null 2>&1" >> /tmp/cron_tmp
            done
            crontab /tmp/cron_tmp
            rm /tmp/cron_tmp
            echo -e "${GREEN}Cronjob set successfully to restart haproxy and vxlan-tunnel(s) every $cron_hours hour(s).${NC}"
            read -p "Press Enter to return to menu..."
            ;;
        *)
            echo "[x] Invalid option. Try again."
            sleep 1
            ;;
    esac
done
