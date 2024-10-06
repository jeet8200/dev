#!/bin/bash

# Define text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
LGREEN='\033[1;32m' # Light Green
NC='\033[0m' # No Color

# Function to handle errors
handle_error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

# Function to update the package lists, upgrade installed packages, and clean up
update_system() {
    if sudo apt update -y && sudo apt upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y; then
        echo -e "${GREEN}System update completed successfully.${NC}"
    else
        handle_error "Failed to update system."
    fi
}

# Function to install sudo and wget
install_utilities() {
    if sudo apt install && sudo apt install ufw -y sudo wget  ; then
        echo -e "${GREEN}Utilities (sudo and wget and ufw ) installed successfully.${NC}"
    else
        handle_error "Failed to install utilities (sudo and wget)."
    fi
}

# Function to install Nginx and obtain SSL certificates
install_nginx() {
    if sudo apt install nginx -y && sudo apt install snapd -y && sudo snap install core && sudo snap install --classic certbot && sudo ln -s /snap/bin/certbot /usr/bin/certbot && sudo certbot --nginx; then
        echo -e "${GREEN}Nginx installed and SSL certificates obtained successfully.${NC}"
    else
        handle_error "Failed to install Nginx or obtain SSL certificates."
    fi
}

# Function to manage Nginx: stop, start, reload, restart
# Define the function to handle adding a new domain
add_new_domain() {
    echo -e "${LGREEN}===== Add New Domain =====${NC}"
    read -p "Enter the domain name (e.g., example.com): " domain_name
    if [ -z "$domain_name" ]; then
        handle_error "Domain name cannot be empty. Please try again."
    else
        sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/$domain_name
        sudo ln -s /etc/nginx/sites-available/$domain_name /etc/nginx/sites-enabled/
        echo -e "${GREEN}Domain $domain_name has been added and enabled.${NC}"
        echo -e "Remember to configure the server block in /etc/nginx/sites-available/$domain_name and reload Nginx."
    fi
}

manage_nginx() {
    echo -e "${LGREEN}===== Nginx Management =====${NC}"
    echo -e " ${YELLOW}1.${NC} Stop Nginx"
    echo -e " ${YELLOW}2.${NC} Start Nginx"
    echo -e " ${YELLOW}3.${NC} Reload Nginx"
    echo -e " ${YELLOW}4.${NC} Restart Nginx"
    echo -e " ${YELLOW}5.${NC} Uninstall Nginx"
    echo -e " ${YELLOW}6.${NC} Add New Domain"  # New option for adding a domain
    echo -e " ${YELLOW}0.${NC} Back"
    echo -e "${LGREEN}============================${NC}"
    read -p "Enter your choice: " nginx_choice
    case $nginx_choice in
        1) sudo systemctl stop nginx ;;
        2) sudo systemctl start nginx ;;
        3) sudo systemctl reload nginx ;;
        4) sudo systemctl restart nginx ;;
        5) uninstall_nginx ;;
        6) add_new_domain ;;  # Calls the function for adding a new domain
        0) return ;;
        *) handle_error "Invalid choice. Please enter a number between 0 and 6." ;;
    esac
    echo -e "${GREEN}Nginx action completed successfully.${NC}"
}


# Function to configure Nginx for wildcard SSL
configure_nginx_wildcard_ssl() {
    read -p "Enter your domain name (e.g., example.com): " domain_name
    
    # Validate the domain name input
    if [[ ! "$domain_name" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        handle_error "Invalid domain name. Please enter a valid domain."
        return 1
    fi

    # Choose the DNS provider
    echo "Choose your DNS provider:"
    echo "1) Cloudflare"
    echo "2) Gcore"
    read -p "Enter the number corresponding to your DNS provider: " dns_provider_choice

    case $dns_provider_choice in
        1)
            dns_plugin="dns-cloudflare"
            read -p "Enter your Cloudflare email: " cloudflare_email
            read -p "Enter your Cloudflare API key: " cloudflare_api_key
            echo

            # Save the Cloudflare API credentials
            cloudflare_credentials_file=~/.secrets/certbot/cloudflare.ini
            mkdir -p $(dirname "$cloudflare_credentials_file")
            echo "dns_cloudflare_email = $cloudflare_email" | sudo tee "$cloudflare_credentials_file" > /dev/null
            echo "dns_cloudflare_api_key = $cloudflare_api_key" | sudo tee -a "$cloudflare_credentials_file" > /dev/null

            # Secure the credentials file
            sudo chmod 600 "$cloudflare_credentials_file"
            ;;
        2)
            dns_plugin="dns-gcore"
            read -p "Enter your Gcore API token: " gcore_api_token
            echo

            # Save the Gcore API credentials
            gcore_credentials_file=~/.secrets/certbot/gcore.ini
            mkdir -p $(dirname "$gcore_credentials_file")
            echo "dns_gcore_api_token = $gcore_api_token" | sudo tee "$gcore_credentials_file" > /dev/null

            # Secure the credentials file
            sudo chmod 600 "$gcore_credentials_file"
            ;;
        *)
            handle_error "Invalid choice. Please choose either 1 for Cloudflare or 2 for Gcore."
            return 1
            ;;
    esac

    # Certbot command with the chosen DNS challenge plugin
    if sudo certbot certonly --$dns_plugin \
            -d "$domain_name" \
            -d "*.$domain_name" \
            --agree-tos --non-interactive --email your-email@example.com; then
        echo -e "${GREEN}Wildcard SSL certificate obtained successfully for $domain_name.${NC}"

        # Configure Nginx to use the obtained certificate
        nginx_config_file="/etc/nginx/sites-available/$domain_name.conf"
        if sudo tee "$nginx_config_file" > /dev/null <<EOL
server {
    listen 443 ssl;
    server_name $domain_name *.$domain_name;

    ssl_certificate /etc/letsencrypt/live/$domain_name/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain_name/privkey.pem;

    location / {
        proxy_pass http://localhost:8080; # Adjust according to your setup
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOL
        then
            echo -e "${GREEN}Nginx configuration updated successfully for $domain_name.${NC}"
            sudo ln -s "$nginx_config_file" /etc/nginx/sites-enabled/
            sudo systemctl reload nginx
        else
            handle_error "Failed to configure Nginx for $domain_name."
            return 1
        fi
    else
        handle_error "Failed to obtain wildcard SSL certificate for $domain_name."
        return 1
    fi

    # Optional: Log the successful SSL configuration
    log_file="/var/log/nginx_ssl_setup.log"
    echo "$(date): Successfully configured wildcard SSL for $domain_name using $dns_plugin" | sudo tee -a "$log_file"
}

# Function to install x-ui
install_x_ui() {
    if bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh); then
        echo -e "${GREEN}x-ui installed successfully.${NC}"
    else
        handle_error "Failed to install x-ui."
    fi
}

# Function to handle Reality-EZ menu
handle_reality_ez() {
    echo -e "${LGREEN}===== Reality-EZ Management =====${NC}"
    echo -e " ${YELLOW}1.${NC} Installation"
    echo -e " ${YELLOW}2.${NC} Manager"
    echo -e " ${YELLOW}3.${NC} Show User Config by Username"
    echo -e " ${YELLOW}4.${NC} Restart"
    echo -e " ${YELLOW}0.${NC} Back"
    echo -e "${LGREEN}==============================${NC}"
    read -p "Enter your choice: " reality_ez_choice
    case $reality_ez_choice in
        1) bash <(curl -sL https://bit.ly/realityez) ;;
        2) bash <(curl -sL https://bit.ly/realityez) -m ;;
        3) read -p "Enter the username: " username; bash <(curl -sL https://bit.ly/realityez) --show-user "$username" ;;
        4) bash <(curl -sL https://bit.ly/realityez) -r ;;
        0) return ;;
        *) handle_error "Invalid choice. Please enter a number between 0 and 4." ;;
    esac
    echo -e "${GREEN}Reality-EZ action completed successfully.${NC}"
}

# Function to install Telegram MTProto proxy
install_telegram_proxy() {
    if curl -L -o mtp_install.sh https://git.io/fj5ru && bash mtp_install.sh; then
        echo -e "${GREEN}Telegram MTProto proxy installed successfully.${NC}"
    else
        handle_error "Failed to install Telegram MTProto proxy."
    fi
}

# Function to install OpenVPN and stunnel
install_openvpn() {
    if sudo apt install openvpn stunnel4 -y; then
        echo -e "${GREEN}OpenVPN and stunnel installed successfully.${NC}"
    else
        handle_error "Failed to install OpenVPN and stunnel."
    fi
}

# Function to install fail2ban
install_fail2ban() {
    if sudo apt install fail2ban -y; then
        echo -e "${GREEN}fail2ban installed successfully.${NC}"
    else
        handle_error "Failed to install fail2ban."
    fi
}

# Function to create a swap file
create_swap() {
    echo -e "${LGREEN}===== Create Swap File =====${NC}"
    echo -e " ${YELLOW}1.${NC} 512M"
    echo -e " ${YELLOW}2.${NC} 1G"
    echo -e " ${YELLOW}3.${NC} 2G"
    read -p "Enter your choice: " swap_size
    case $swap_size in
        1) swap_size="512M" ;;
        2) swap_size="1G" ;;
        3) swap_size="2G" ;;
        *) handle_error "Invalid choice. Please select 1, 2, or 3." ;;
    esac
    
    case $swap_size in
        512M)
            if sudo fallocate -l 512M /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile && echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab; then
                echo -e "${GREEN}Swap file created successfully.${NC}"
            else
                handle_error "Failed to create swap file."
            fi
            ;;
        1G)
            if sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile && echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab; then
                echo -e "${GREEN}Swap file created successfully.${NC}"
            else
                handle_error "Failed to create swap file."
            fi
            ;;
        2G)
            if sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile && echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab; then
                echo -e "${GREEN}Swap file created successfully.${NC}"
            else
                handle_error "Failed to create swap file."
            fi
            ;;
        *)
            handle_error "Invalid swap size. Choose 512M, 1G, or 2G."
            ;;
    esac
}
# Function to change SSH port
change_ssh_port() {
    # Suggested ports - Commonly recommended alternatives to port 22
    suggested_ports=("2022" "2222" "2200" "8022" "9222")
    
    echo "Please select a new SSH port from the suggested options below:"
    for i in "${!suggested_ports[@]}"; do
        echo "$((i + 1))) ${suggested_ports[$i]}"
    done
    
    read -p "Enter the number corresponding to your choice (1-5) or enter a custom port: " port_choice

    if [[ $port_choice =~ ^[1-5]$ ]]; then
        new_ssh_port=${suggested_ports[$((port_choice - 1))]}
    elif [[ $port_choice =~ ^[0-9]+$ && $port_choice -ge 1024 && $port_choice -le 65535 ]]; then
        new_ssh_port=$port_choice
    else
        handle_error "Invalid choice. Please enter a valid port number."
        return 1
    fi

    # Change the SSH port in the sshd_config file
    if sudo sed -i "s/#Port 22/Port $new_ssh_port/g" /etc/ssh/sshd_config && sudo systemctl restart ssh; then
        echo -e "${GREEN}SSH port changed successfully to $new_ssh_port.${NC}"
    else
        handle_error "Failed to change SSH port."
        return 1
    fi

    # Ensure UFW is installed
    if ! command -v ufw &> /dev/null; then
        echo "UFW is not installed. Installing UFW..."
        if sudo apt-get update && sudo apt-get install ufw -y; then
            echo -e "${GREEN}UFW installed successfully.${NC}"
        else
            handle_error "Failed to install UFW."
            return 1
        fi
    else
        echo -e "${GREEN}UFW is already installed.${NC}"
    fi

    # Enable UFW if not already enabled
    if sudo ufw status | grep -q "Status: inactive"; then
        echo "UFW is not active. Enabling UFW..."
        if sudo ufw enable; then
            echo -e "${GREEN}UFW enabled successfully.${NC}"
        else
            handle_error "Failed to enable UFW."
            return 1
        fi
    else
        echo -e "${GREEN}UFW is already active.${NC}"
    fi

    # Add rate-limited rule for the new SSH port
    echo "Adding UFW rule for SSH port $new_ssh_port with rate limiting..."
    if sudo ufw limit "$new_ssh_port"/tcp; then
        echo -e "${GREEN}UFW rule added successfully for port $new_ssh_port with rate limiting.${NC}"
    else
        handle_error "Failed to add UFW rule for SSH port $new_ssh_port."
        return 1
    fi
}

# Function to uninstall Nginx
uninstall_nginx() {
    if sudo apt remove --purge nginx -y && sudo rm -rf /etc/nginx; then
        echo -e "${GREEN}Nginx uninstalled successfully.${NC}"
    else
        handle_error "Failed to uninstall Nginx."
    fi
}


# Function to install Hiddify Panel
install_hiddify_panel() {
    if bash <(curl i.hiddify.com/release); then
        echo -e "${GREEN}Hiddify Panel installed successfully.${NC}"
    else
        handle_error "Failed to install Hiddify Panel."
    fi
}
# Function to add a cron job to reboot the system every 2 days
schedule_reboot() {
    if (crontab -l ; echo "0 0 */2 * * sudo /sbin/reboot") | crontab -; then
        echo -e "${GREEN}Scheduled system reboot every 2 days.${NC}"
    else
        handle_error "Failed to schedule system reboot."
    fi
}
# Install Reverse nginx
setup_nginx_reverse_proxy() {
    # Check if NGINX is already installed
	if [ -d "/etc/letsencrypt/live/$saved_domain" ]; then
	    echo -e "${yellow}×××××××××××××××××××××××${rest}"
		echo -e "${cyan}N R P${green} is already installed.${rest}"
		echo -e "${yellow}×××××××××××××××××××××××${rest}"
	else
	# Ask the user for the domain name
	echo -e "${yellow}×××××××××××××××××××××××${rest}"
	read -p "Enter your domain name: " domain
	echo -e "${yellow}×××××××××××××××××××××××${rest}"
	read -p "Enter GRPC Path (Service Name) [default: grpc]: " grpc_path
	grpc_path=${grpc_path:-grpc}
	echo -e "${yellow}×××××××××××××××××××××××${rest}"
	read -p "Enter WebSocket Path (Service Name) [default: ws]: " ws_path
	ws_path=${ws_path:-ws}
	echo -e "${yellow}×××××××××××××××××××××××${rest}"
	check_dependencies
	
	echo "$domain" > "$d_f"
	# Copy default NGINX config to your website
	sudo cp /etc/nginx/sites-available/default "/etc/nginx/sites-available/$domain" || display_error "Failed to copy NGINX config"
	
	# Enable your website
	sudo ln -s "/etc/nginx/sites-available/$domain" "/etc/nginx/sites-enabled/" || display_error "Failed to enable your website"
	
	# Remove default_server from the copied config
	sudo sed -i -e 's/listen 80 default_server;/listen 80;/g' \
	              -e 's/listen \[::\]:80 default_server;/listen \[::\]:80;/g' \
	              -e "s/server_name _;/server_name $domain;/g" "/etc/nginx/sites-available/$domain" || display_error "Failed to modify NGINX config"
	
	# Restart NGINX service
	sudo systemctl restart nginx || display_error "Failed to restart NGINX service"
	
	# Allow ports in firewall
	sudo ufw allow 80/tcp || display_error "Failed to allow port 80"
	sudo ufw allow 443/tcp || display_error "Failed to allow port 443"
	
	# Get a free SSL certificate
	echo -e "${yellow}×××××××××××××××××××××××${rest}"
	echo -e "${green}Get SSL certificate ${rest}"
	sudo certbot --nginx -d "$domain" --register-unsafely-without-email --non-interactive --agree-tos --redirect || display_error "Failed to obtain SSL certificate"
	
	# NGINX config file content
	cat <<EOL > /etc/nginx/sites-available/$domain
server {
        root /var/www/html;
        
        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;
        server_name $domain;
        
        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files \$uri \$uri/ =404;
        }
        # GRPC configuration
	    location ~ ^/$grpc_path/(?<port>\d+)/(.*)$ {
	        if (\$content_type !~ "application/grpc") {
	            return 404;
	        }
	        set \$grpc_port \$port;
	        client_max_body_size 0;
	        client_body_buffer_size 512k;
	        grpc_set_header X-Real-IP \$remote_addr;
	        client_body_timeout 1w;
	        grpc_read_timeout 1w;
	        grpc_send_timeout 1w;
	        grpc_pass grpc://127.0.0.1:\$grpc_port;
	    }
	    # WebSocket configuration
	    location ~ ^/$ws_path/(?<port>\d+)$ {
	        if (\$http_upgrade != "websocket") {
	            return 404;
	        }
	        set \$ws_port \$port;
	        proxy_pass http://127.0.0.1:\$ws_port/;
	        proxy_redirect off;
	        proxy_http_version 1.1;
	        proxy_set_header Upgrade \$http_upgrade;
	        proxy_set_header Connection "upgrade";
	        proxy_set_header Host \$host;
	        proxy_set_header X-Real-IP \$remote_addr;
	        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
	    }
	
    listen [::]:443 ssl http2 ipv6only=on; # managed by Certbot
    listen 443 ssl http2; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}
server {
    if (\$host = $domain) {
        return 301 https://\$host\$request_uri;
    } # managed by Certbot
        listen 80;
        listen [::]:80;
        server_name $domain;
    return 404; # managed by Certbot
}
EOL
	
	# Restart NGINX service
	sudo systemctl restart nginx || display_error "Failed to restart NGINX service"
	check_installation
  fi
}
# Main menu
main_menu() {
    while true; do
        echo -e "${LGREEN}===== Main Menu =====${NC}"
        echo -e " ${YELLOW}1.${NC} Update System"
        echo -e " ${YELLOW}2.${NC} Install Utilities"
        echo -e " ${YELLOW}3.${NC} Install Nginx"
        echo -e " ${YELLOW}4.${NC} Manage Nginx"
        echo -e " ${YELLOW}5.${NC} Configure Nginx Wildcard SSL"
        echo -e " ${YELLOW}6.${NC} Install x-ui"
        echo -e " ${YELLOW}7.${NC} Reality-EZ Menu"
        echo -e " ${YELLOW}8.${NC} Install Hiddify Panel Ubuntu 22+"
        echo -e " ${YELLOW}9.${NC} Install Telegram MTProto Proxy"
        echo -e " ${YELLOW}10.${NC} Install OpenVPN and Stunnel"
        echo -e " ${YELLOW}11.${NC} Install fail2ban"
        echo -e " ${YELLOW}12.${NC} Create Swap File"
        echo -e " ${YELLOW}13.${NC} Change SSH port"
        echo -e " ${YELLOW}14.${NC} Schedule system reboot every 2 days"
        echo -e " ${YELLOW}15.${NC} Uninstall Nginx"
        echo -e " ${YELLOW}16.${NC} Nginx reverse proxy setup with path for x-ui v2ray configs"
        echo -e " ${YELLOW}0.${NC} Exit"
        echo -e "${LGREEN}=====================${NC}"
        read -p "Enter your choice: " main_choice
        case $main_choice in
            1) update_system ;;
            2) install_utilities ;;
            3) install_nginx ;;
            4) manage_nginx ;;
            5) configure_nginx_wildcard_ssl ;;
            6) install_x_ui ;;
            7) handle_reality_ez ;;
            8) install_hiddify_panel ;;
            9) install_telegram_proxy ;;
            10) install_openvpn ;;
            11) install_fail2ban ;;
            12) create_swap ;;
            13) change_ssh_port ;;
            14) schedule_reboot ;;
            15) uninstall_nginx ;;
	    16) setup_nginx_reverse_proxy;;
             0) exit 0 ;;
            *) handle_error "Invalid choice. Please enter a number between 0 and 13." ;;
        esac
    done
}

# Start the main menu
main_menu
