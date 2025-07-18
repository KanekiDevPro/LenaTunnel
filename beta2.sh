#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
NC='\033[0m'

echo "[*] Updating and installing dependencies..."
sudo apt update -y
sudo apt install -y iproute2 net-tools grep awk sudo iputils-ping jq curl haproxy iptables

main_menu() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo "+-------------------------------------------------------------------------+"
    echo "| Multi-VXLAN Setup                                                       |"
    echo "+-------------------------------------------------------------------------+"
    echo -e "| Telegram Channel : ${MAGENTA}@AminiDev ${NC}|"
    echo "+-------------------------------------------------------------------------+"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo "+-------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Please choose your role:${NC}"
    echo "+-------------------------------------------------------------------------+"
    echo -e "1- IRAN (central server)"
    echo -e "2- FOREIGN (multiple remote servers)"
    echo "+-------------------------------------------------------------------------+"
}

iran_menu() {
    clear
    echo "+-----------------------------------------------------------+"
    echo "| IRAN Role Menu                                            |"
    echo "+-----------------------------------------------------------+"
    echo -e "1- Install VXLAN tunnels to foreign servers"
    echo -e "2- Uninstall all tunnels"
    echo "+-----------------------------------------------------------+"
}

foreign_menu() {
    clear
    echo "+-----------------------------------------------------------+"
    echo "| FOREIGN Role Menu                                         |"
    echo "+-----------------------------------------------------------+"
    echo -e "1- Install VXLAN tunnel to IRAN server"
    echo -e "2- Uninstall tunnel"
    echo "+-----------------------------------------------------------+"
}

# IRAN functions
uninstall_all_vxlan() {
    echo "[!] Deleting all VXLAN interfaces and cleaning up..."
    for i in $(ip -d link show | grep -o 'vxlan[0-9]\+'); do
        ip link del $i 2>/dev/null
    done
    rm -f /usr/local/bin/vxlan_bridge*.sh
    systemctl list-units | grep 'vxlan-tunnel-' | awk '{print $1}' | xargs -r systemctl disable --now 2>/dev/null
    rm -f /etc/systemd/system/vxlan-tunnel-*.service
    systemctl daemon-reload
    echo "[+] All VXLAN tunnels deleted."
}

install_foreign_tunnels() {
    IRAN_IP=$(hostname -I | awk '{print $1}')
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    VNI_BASE=100

    read -p "How many foreign servers do you want to connect? " N
    if ! [[ "$N" =~ ^[0-9]+$ ]] || ((N < 1)); then
        echo "Invalid number."
        return
    fi

    declare -a FOREIGN_IPS
    declare -a PORTS

    for ((i=1;i<=N;i++)); do
        read -p "Foreign server #$i real IP: " FIP
        FOREIGN_IPS+=("$FIP")
        while true; do
            read -p "VXLAN UDP Port for #$i (1~64435): " PORT
            if [[ $PORT =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 64435 )); then
                PORTS+=("$PORT")
                break
            else
                echo "Invalid port. Try again."
            fi
        done
    done

    for ((i=0;i<N;i++)); do
        FIP=${FOREIGN_IPS[$i]}
        PORT=${PORTS[$i]}
        VNI=$((VNI_BASE + i))
        VXLAN_IF="vxlan${VNI}"
        VXLAN_IP="30.0.0.$((i+2))/24"  # 30.0.0.2, 30.0.0.3, ...

        echo "----------------------------------------------"
        echo "[+] Setting up VXLAN for foreign #$((i+1))"
        echo "[+] Interface: $VXLAN_IF"
        echo "[+] Local IP: $IRAN_IP"
        echo "[+] Remote IP: $FIP"
        echo "[+] Port: $PORT"
        echo "[+] VXLAN IP: $VXLAN_IP"
        echo "----------------------------------------------"

        ip link add $VXLAN_IF type vxlan id $VNI local $IRAN_IP remote $FIP dev $INTERFACE dstport $PORT nolearning
        ip addr add $VXLAN_IP dev $VXLAN_IF
        ip link set $VXLAN_IF up

        iptables -I INPUT 1 -p udp --dport $PORT -j ACCEPT
        iptables -I INPUT 1 -s $FIP -j ACCEPT
        iptables -I INPUT 1 -s ${VXLAN_IP%/*} -j ACCEPT

        # Create systemd service for each VXLAN
        cat <<EOF > /usr/local/bin/vxlan_bridge_${VNI}.sh
#!/bin/bash
ip link add $VXLAN_IF type vxlan id $VNI local $IRAN_IP remote $FIP dev $INTERFACE dstport $PORT nolearning
ip addr add $VXLAN_IP dev $VXLAN_IF
ip link set $VXLAN_IF up
( while true; do ping -c 1 $FIP >/dev/null 2>&1; sleep 30; done ) &
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
    done
    echo "${GREEN}[✓] All foreign VXLAN tunnels are set up.${NC}"
}

# FOREIGN functions
uninstall_vxlan() {
    for i in $(ip -d link show | grep -o 'vxlan[0-9]\+'); do
        ip link del $i 2>/dev/null
    done
    rm -f /usr/local/bin/vxlan_bridge*.sh
    systemctl list-units | grep 'vxlan-tunnel-' | awk '{print $1}' | xargs -r systemctl disable --now 2>/dev/null
    rm -f /etc/systemd/system/vxlan-tunnel-*.service
    systemctl daemon-reload
    echo "[+] VXLAN tunnel deleted."
}

install_iran_tunnel() {
    FOREIGN_IP=$(hostname -I | awk '{print $1}')
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    read -p "Enter IRAN server real IP: " IRAN_IP
    read -p "Enter assigned internal IP for this server (example: 30.0.0.X): " VXLAN_IP
    while true; do
        read -p "VXLAN UDP Port (as assigned by IRAN): " PORT
        if [[ $PORT =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 64435 )); then
            break
        else
            echo "Invalid port. Try again."
        fi
    done
    read -p "Enter VXLAN ID (as assigned by IRAN): " VNI
    VXLAN_IF="vxlan${VNI}"

    echo "----------------------------------------------"
    echo "[+] Setting up VXLAN to IRAN"
    echo "[+] Interface: $VXLAN_IF"
    echo "[+] Local IP: $FOREIGN_IP"
    echo "[+] Remote IP: $IRAN_IP"
    echo "[+] Port: $PORT"
    echo "[+] VXLAN IP: $VXLAN_IP"
    echo "[+] VNI: $VNI"
    echo "----------------------------------------------"

    ip link add $VXLAN_IF type vxlan id $VNI local $FOREIGN_IP remote $IRAN_IP dev $INTERFACE dstport $PORT nolearning
    ip addr add $VXLAN_IP/24 dev $VXLAN_IF
    ip link set $VXLAN_IF up

    iptables -I INPUT 1 -p udp --dport $PORT -j ACCEPT
    iptables -I INPUT 1 -s $IRAN_IP -j ACCEPT
    iptables -I INPUT 1 -s ${VXLAN_IP%/*} -j ACCEPT

    # Create systemd service
    cat <<EOF > /usr/local/bin/vxlan_bridge_${VNI}.sh
#!/bin/bash
ip link add $VXLAN_IF type vxlan id $VNI local $FOREIGN_IP remote $IRAN_IP dev $INTERFACE dstport $PORT nolearning
ip addr add $VXLAN_IP/24 dev $VXLAN_IF
ip link set $VXLAN_IF up
( while true; do ping -c 1 $IRAN_IP >/dev/null 2>&1; sleep 30; done ) &
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
}

# Main role selection
while true; do
    main_menu
    read -p "Enter your role [1-IRAN / 2-FOREIGN]: " role
    case $role in
        1)
            # IRAN role
            while true; do
                iran_menu
                read -p "Enter your choice [1-2]: " main_action
                case $main_action in
                    1)
                        install_foreign_tunnels
                        read -p "Press Enter to return to menu..."
                        ;;
                    2)
                        uninstall_all_vxlan
                        read -p "Press Enter to return to menu..."
                        ;;
                    *)
                        echo "[x] Invalid option. Try again."
                        sleep 1
                        ;;
                esac
            done
            ;;
        2)
            # FOREIGN role
            while true; do
                foreign_menu
                read -p "Enter your choice [1-2]: " main_action
                case $main_action in
                    1)
                        install_iran_tunnel
                        read -p "Press Enter to return to menu..."
                        ;;
                    2)
                        uninstall_vxlan
                        read -p "Press Enter to return to menu..."
                        ;;
                    *)
                        echo "[x] Invalid option. Try again."
                        sleep 1
                        ;;
                esac
            done
            ;;
        *)
            echo "[x] Invalid role. Try again."
            sleep 1
            ;;
    esac
done
