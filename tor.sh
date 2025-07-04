#!/bin/bash

TORRC_FILE="/etc/tor/torrc"
SERVICE_NAME="tor"
ONION_DIR="/var/lib/tor/3xui_onion"

function install_tor() {
    echo "[+] Installing Tor..."
    sudo apt update && sudo apt install -y tor obfs4proxy
    sudo systemctl enable tor
    sudo systemctl start tor
    echo "[+] Tor installed and started."
}

function configure_exit_country() {
    read -rp "Enter 2-letter country code for ExitNodes (e.g., us, de, ch): " country
    sed -i '/^ExitNodes/d' "$TORRC_FILE"
    sed -i '/^StrictNodes/d' "$TORRC_FILE"
    echo "ExitNodes {$country}" | sudo tee -a "$TORRC_FILE"
    echo "StrictNodes 1" | sudo tee -a "$TORRC_FILE"
    sudo systemctl restart tor
    echo "[+] Exit country set to $country and Tor restarted."
}

function change_socks_port() {
    read -rp "Enter new Tor SOCKS port (e.g., 9050): " port
    sed -i '/^SocksPort/d' "$TORRC_FILE"
    echo "SocksPort 127.0.0.1:$port" | sudo tee -a "$TORRC_FILE"
    sudo systemctl restart tor
    echo "[+] SOCKS port changed to $port and Tor restarted."
}

function harden_tor_firewall() {
    echo "[+] Applying firewall rules to prevent leaks..."
    sudo iptables -F
    sudo iptables -P OUTPUT DROP
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A OUTPUT -m owner --uid-owner debian-tor -j ACCEPT
    sudo iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
    echo "[+] Firewall leak protection applied."
}

function setup_hidden_service() {
    read -rp "Enter 3x-ui local port (e.g., 54321): " localport
    sudo mkdir -p "$ONION_DIR"
    sudo chown -R debian-tor:debian-tor "$ONION_DIR"
    sudo chmod 700 "$ONION_DIR"
    
    if ! grep -q "HiddenServiceDir $ONION_DIR" "$TORRC_FILE"; then
        echo -e "\nHiddenServiceDir $ONION_DIR" | sudo tee -a "$TORRC_FILE"
        echo "HiddenServicePort 80 127.0.0.1:$localport" | sudo tee -a "$TORRC_FILE"
    fi
    
    sudo systemctl restart tor
    sleep 3

    onion=$(sudo cat "$ONION_DIR/hostname")
    echo "[+] .onion address created: http://$onion"
}

function uninstall_tor() {
    echo "[!] Uninstalling Tor and removing config..."
    sudo systemctl stop tor
    sudo apt purge --auto-remove -y tor obfs4proxy
    sudo rm -rf /etc/tor /var/lib/tor /var/log/tor
    sudo iptables -F
    echo "[+] Tor and all related files removed."
}

function main_menu() {
    while true; do
        echo "=========================="
        echo "     Tor Manager Script"
        echo "=========================="
        echo "1) Install and configure Tor"
        echo "2) Set Exit Country"
        echo "3) Change SOCKS Port"
        echo "4) Apply DNS & Firewall leak protection"
        echo "5) Set up .onion for 3x-ui panel"
        echo "6) Uninstall Tor completely"
        echo "7) Exit"
        echo "=========================="
        read -rp "Choose an option [1-7]: " opt

        case $opt in
            1) install_tor ;;
            2) configure_exit_country ;;
            3) change_socks_port ;;
            4) harden_tor_firewall ;;
            5) setup_hidden_service ;;
            6) uninstall_tor ;;
            7) echo "Exiting."; break ;;
            *) echo "Invalid option." ;;
        esac
    done
}

main_menu
