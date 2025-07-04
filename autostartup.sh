#!/bin/bash

# Define text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
LGREEN='\033[1;32m' # Light Green
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to handle errors
handle_error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

# Function to validate input
validate_input() {
    if [[ -z "$1" ]]; then
        handle_error "Input cannot be empty"
    fi
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        handle_error "Please run as root"
    fi
}

### Function Management Section ###

# Function to list all available functions
list_functions() {
    echo -e "${GREEN}Available functions:${NC}"
    grep -E '^[a-zA-Z0-9_]+\(\)' "$0" | awk -F '(' '{print NR ") " $1}'
}

# Function to add a new function
add_function() {
    read -p "Enter the function name to add: " func_name
    validate_input "$func_name"

    # Check if function already exists
    if grep -q "^$func_name()" "$0"; then
        echo -e "${YELLOW}Function '$func_name' already exists!${NC}"
        return 1
    fi

    # Validate function name
    if [[ ! "$func_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
        echo -e "${RED}Invalid function name! Only letters, numbers and underscores are allowed.${NC}"
        return 1
    fi

    echo -e "${YELLOW}Enter the function code (end with an empty line):${NC}"
    func_code=""
    while IFS= read -r line; do
        [[ -z "$line" ]] && break
        func_code+="$line"$'\n'
    done

    # Create backup before modifying
    cp "$0" "$0.bak"

    # Append the function to the script
    echo -e "\n$func_name() {\n$func_code\n}" >> "$0"
    echo -e "${GREEN}Function '$func_name' added successfully!${NC}"

    # Make sure the script remains executable
    chmod +x "$0"
}

# Function to remove an existing function
remove_function() {
    list_functions
    read -p "Enter the function name to remove: " func_name
    validate_input "$func_name"

    # Check if function exists
    if ! grep -q "^$func_name()" "$0"; then
        echo -e "${RED}Function '$func_name' does not exist!${NC}"
        return 1
    fi

    # Create backup before modifying
    cp "$0" "$0.bak"

    # Remove the function
    sed -i "/^$func_name()/,/^}/d" "$0"
    echo -e "${GREEN}Function '$func_name' removed successfully!${NC}"
}

# Function to manage menu items
manage_functions() {
    while true; do
        echo -e "\n${LGREEN}==== Manage Functions ====${NC}"
        echo "1) List functions"
        echo "2) Add function"
        echo "3) Remove function"
        echo "4) Back to main menu"
        read -p "Choose an option: " choice

        case $choice in
            1) list_functions ;;
            2) add_function ;;
            3) remove_function ;;
            4) break ;;
            *) echo -e "${RED}Invalid choice!${NC}" ;;
        esac
    done
}

### System Management Functions ###

update_system() {
    echo -e "${YELLOW}Updating system packages...${NC}"
    if sudo apt update -y && sudo apt upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y; then
        echo -e "${GREEN}System update completed successfully.${NC}"
    else
        handle_error "Failed to update system."
    fi
}

install_utilities() {
    echo -e "${YELLOW}Installing basic utilities...${NC}"
    if sudo apt install ufw wget sudo -y; then
        echo -e "${GREEN}Utilities (ufw, wget, sudo) installed successfully.${NC}"
    else
        handle_error "Failed to install utilities."
    fi
}

install_nginx() {
    echo -e "${YELLOW}Installing Nginx and SSL certificates...${NC}"
    if sudo apt install nginx -y && \
       sudo apt install snapd -y && \
       sudo snap install core && \
       sudo snap install --classic certbot && \
       sudo ln -s /snap/bin/certbot /usr/bin/certbot && \
       sudo certbot --nginx; then
        echo -e "${GREEN}Nginx installed and SSL certificates obtained successfully.${NC}"
    else
        handle_error "Failed to install Nginx or obtain SSL certificates."
    fi
}

uninstall_nginx() {
    echo -e "${YELLOW}Uninstalling Nginx...${NC}"
    if sudo apt remove --purge nginx -y && sudo rm -rf /etc/nginx; then
        echo -e "${GREEN}Nginx uninstalled successfully.${NC}"
    else
        handle_error "Failed to uninstall Nginx."
    fi
}

add_new_domain() {
    echo -e "${LGREEN}===== Add New Domain =====${NC}"
    read -p "Enter the domain name (e.g., example.com): " domain_name
    validate_input "$domain_name"

    sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/"$domain_name"
    sudo ln -s /etc/nginx/sites-available/"$domain_name" /etc/nginx/sites-enabled/
    echo -e "${GREEN}Domain $domain_name has been added and enabled.${NC}"
    echo -e "Remember to configure the server block in /etc/nginx/sites-available/$domain_name and reload Nginx."
}

manage_nginx() {
    while true; do
        echo -e "\n${LGREEN}===== Nginx Management =====${NC}"
        echo "1) Stop Nginx"
        echo "2) Start Nginx"
        echo "3) Reload Nginx"
        echo "4) Restart Nginx"
        echo "5) Uninstall Nginx"
        echo "6) Add New Domain"
        echo "0) Back"
        read -p "Enter your choice: " nginx_choice

        case $nginx_choice in
            1) sudo systemctl stop nginx ;;
            2) sudo systemctl start nginx ;;
            3) sudo systemctl reload nginx ;;
            4) sudo systemctl restart nginx ;;
            5) uninstall_nginx ;;
            6) add_new_domain ;;
            0) break ;;
            *) echo -e "${RED}Invalid choice!${NC}" ;;
        esac
    done
}

configure_nginx_wildcard_ssl() {
    read -p "Enter your domain name (e.g., example.com): " domain_name
    
    # Validate the domain name input
    if [[ ! "$domain_name" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        handle_error "Invalid domain name. Please enter a valid domain."
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

            # Save the Cloudflare API credentials
            cloudflare_credentials_file=~/.secrets/certbot/cloudflare.ini
            mkdir -p "$(dirname "$cloudflare_credentials_file")"
            echo "dns_cloudflare_email = $cloudflare_email" | sudo tee "$cloudflare_credentials_file" > /dev/null
            echo "dns_cloudflare_api_key = $cloudflare_api_key" | sudo tee -a "$cloudflare_credentials_file" > /dev/null
            sudo chmod 600 "$cloudflare_credentials_file"
            ;;
        2)
            dns_plugin="dns-gcore"
            read -p "Enter your Gcore API token: " gcore_api_token

            # Save the Gcore API credentials
            gcore_credentials_file=~/.secrets/certbot/gcore.ini
            mkdir -p "$(dirname "$gcore_credentials_file")"
            echo "dns_gcore_api_token = $gcore_api_token" | sudo tee "$gcore_credentials_file" > /dev/null
            sudo chmod 600 "$gcore_credentials_file"
            ;;
        *)
            handle_error "Invalid choice. Please choose either 1 for Cloudflare or 2 for Gcore."
            ;;
    esac

    # Get SSL certificate
    if sudo certbot certonly --"$dns_plugin" \
            -d "$domain_name" \
            -d "*.$domain_name" \
            --agree-tos --non-interactive --email admin@"$domain_name"; then
        echo -e "${GREEN}Wildcard SSL certificate obtained successfully for $domain_name.${NC}"
    else
        handle_error "Failed to obtain wildcard SSL certificate."
    fi
}

### Security Functions ###

change_ssh_port() {
    # Suggested ports
    suggested_ports=("2022" "2222" "2200" "8022" "9222")
    
    echo "Please select a new SSH port:"
    for i in "${!suggested_ports[@]}"; do
        echo "$((i + 1))) ${suggested_ports[$i]}"
    done
    
    read -p "Enter your choice (1-5) or a custom port (1024-65535): " port_choice

    if [[ $port_choice =~ ^[1-5]$ ]]; then
        new_ssh_port=${suggested_ports[$((port_choice - 1))]}
    elif [[ $port_choice =~ ^[0-9]+$ && $port_choice -ge 1024 && $port_choice -le 65535 ]]; then
        new_ssh_port=$port_choice
    else
        handle_error "Invalid port number. Must be between 1024 and 65535."
    fi

    # Change SSH port
    sudo sed -i "s/^#Port 22/Port $new_ssh_port/" /etc/ssh/sshd_config
    sudo systemctl restart sshd
    
    # Configure UFW
    if ! command -v ufw >/dev/null; then
        sudo apt install ufw -y
    fi
    
    sudo ufw allow "$new_ssh_port"/tcp
    sudo ufw limit "$new_ssh_port"/tcp
    echo -e "${GREEN}SSH port changed to $new_ssh_port and UFW configured.${NC}"
}

install_fail2ban() {
    echo -e "${YELLOW}Installing fail2ban...${NC}"
    if sudo apt install fail2ban -y; then
        echo -e "${GREEN}fail2ban installed successfully.${NC}"
    else
        handle_error "Failed to install fail2ban."
    fi
}

### Utility Functions ###

create_swap() {
    echo -e "${LGREEN}===== Create Swap File =====${NC}"
    echo "1) 512MB"
    echo "2) 1GB"
    echo "3) 2GB"
    read -p "Enter your choice: " swap_size
    
    case $swap_size in
        1) swap_size="512M" ;;
        2) swap_size="1G" ;;
        3) swap_size="2G" ;;
        *) handle_error "Invalid choice. Please select 1, 2, or 3." ;;
    esac
    
    if sudo fallocate -l "$swap_size" /swapfile && \
       sudo chmod 600 /swapfile && \
       sudo mkswap /swapfile && \
       sudo swapon /swapfile && \
       echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab; then
        echo -e "${GREEN}Swap file ($swap_size) created successfully.${NC}"
    else
        handle_error "Failed to create swap file."
    fi
}

schedule_reboot() {
    if (crontab -l ; echo "0 0 */2 * * /sbin/reboot") | crontab -; then
        echo -e "${GREEN}Scheduled system reboot every 2 days.${NC}"
    else
        handle_error "Failed to schedule system reboot."
    fi
}

### Additional Services ###

install_x_ui() {
    echo -e "${YELLOW}Installing x-ui...${NC}"
    if bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh); then
        echo -e "${GREEN}x-ui installed successfully.${NC}"
    else
        handle_error "Failed to install x-ui."
    fi
}

handle_reality_ez() {
    while true; do
        echo -e "\n${LGREEN}===== Reality-EZ Management =====${NC}"
        echo "1) Installation"
        echo "2) Manager"
        echo "3) Show User Config by Username"
        echo "4) Restart"
        echo "0) Back"
        read -p "Enter your choice: " reality_ez_choice
        
        case $reality_ez_choice in
            1) bash <(curl -sL https://bit.ly/realityez) ;;
            2) bash <(curl -sL https://bit.ly/realityez) -m ;;
            3) 
                read -p "Enter the username: " username
                bash <(curl -sL https://bit.ly/realityez) --show-user "$username" ;;
            4) bash <(curl -sL https://bit.ly/realityez) -r ;;
            0) break ;;
            *) echo -e "${RED}Invalid choice!${NC}" ;;
        esac
    done
}

install_telegram_proxy() {
    echo -e "${YELLOW}Installing Telegram MTProto proxy...${NC}"
    if curl -L -o mtp_install.sh https://git.io/fj5ru && bash mtp_install.sh; then
        echo -e "${GREEN}Telegram MTProto proxy installed successfully.${NC}"
    else
        handle_error "Failed to install Telegram MTProto proxy."
    fi
}

install_openvpn() {
    echo -e "${YELLOW}Installing OpenVPN and stunnel...${NC}"
    if sudo apt install openvpn stunnel4 -y; then
        echo -e "${GREEN}OpenVPN and stunnel installed successfully.${NC}"
    else
        handle_error "Failed to install OpenVPN and stunnel."
    fi
}

install_hiddify_panel() {
    echo -e "${YELLOW}Installing Hiddify Panel...${NC}"
    if bash <(curl i.hiddify.com/release); then
        echo -e "${GREEN}Hiddify Panel installed successfully.${NC}"
    else
        handle_error "Failed to install Hiddify Panel."
    fi
}

### Nginx Reverse Proxy ###

nginx_reverseProxy() {
    # Check for root user
    check_root

    # Detect the Linux distribution
    detect_distribution() {
        local supported_distributions=("ubuntu" "debian" "centos" "fedora")
        
        if [ -f /etc/os-release ]; then
            source /etc/os-release
            if [[ "${ID}" = "ubuntu" || "${ID}" = "debian" || "${ID}" = "centos" || "${ID}" = "fedora" ]]; then
                p_m="apt-get"
                [ "${ID}" = "centos" ] && p_m="yum"
                [ "${ID}" = "fedora" ] && p_m="dnf"
            else
                echo "Unsupported distribution!"
                exit 1
            fi
        else
            echo "Unsupported distribution!"
            exit 1
        fi
    }

    # Check dependencies
    check_dependencies() {
        detect_distribution
        sudo "${p_m}" -y update && sudo "${p_m}" -y upgrade
        local dependencies=("nginx" "git" "wget" "certbot" "ufw" "python3-certbot-nginx")
        
        for dep in "${dependencies[@]}"; do
            if ! command -v "${dep}" &> /dev/null; then
                echo -e "${YELLOW}${dep} is not installed. Installing...${NC}"
                sudo "${p_m}" install "${dep}" -y
            fi
        done
    }

    # Store domain name
    d_f="/etc/nginx/d.txt"
    # Read domain from file
    saved_domain=$(cat "$d_f" 2>/dev/null)

    # Install Reverse nginx
    install() {
        # Check if NGINX is already installed
        if [ -d "/etc/letsencrypt/live/$saved_domain" ]; then
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${CYAN}N R P${GREEN} is already installed.${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        else
            # Ask the user for the domain name
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            read -p "Enter your domain name: " domain
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            read -p "Enter GRPC Path (Service Name) [default: grpc]: " grpc_path
            grpc_path=${grpc_path:-grpc}
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            read -p "Enter WebSocket Path (Service Name) [default: ws]: " ws_path
            ws_path=${ws_path:-ws}
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            check_dependencies
            
            echo "$domain" > "$d_f"
            # Copy default NGINX config to your website
            sudo cp /etc/nginx/sites-available/default "/etc/nginx/sites-available/$domain" || handle_error "Failed to copy NGINX config"
            
            # Enable your website
            sudo ln -s "/etc/nginx/sites-available/$domain" "/etc/nginx/sites-enabled/" || handle_error "Failed to enable your website"
            
            # Remove default_server from the copied config
            sudo sed -i -e 's/listen 80 default_server;/listen 80;/g' \
                          -e 's/listen \[::\]:80 default_server;/listen \[::\]:80;/g' \
                          -e "s/server_name _;/server_name $domain;/g" "/etc/nginx/sites-available/$domain" || handle_error "Failed to modify NGINX config"
            
            # Restart NGINX service
            sudo systemctl restart nginx || handle_error "Failed to restart NGINX service"
            
            # Allow ports in firewall
            sudo ufw allow 80/tcp || handle_error "Failed to allow port 80"
            sudo ufw allow 443/tcp || handle_error "Failed to allow port 443"
            
            # Get a free SSL certificate
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${GREEN}Get SSL certificate ${NC}"
            sudo certbot --nginx -d "$domain" --register-unsafely-without-email --non-interactive --agree-tos --redirect || handle_error "Failed to obtain SSL certificate"
            
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
            sudo systemctl restart nginx || handle_error "Failed to restart NGINX service"
            check_installation
        fi
    }

    # Check installation status
    check_installation() {
        if systemctl is-active --quiet nginx && [ -f "/etc/nginx/sites-available/$domain" ]; then
            (crontab -l 2>/dev/null | grep -v 'certbot renew --nginx --force-renewal --non-interactive --post-hook "nginx -s reload"' ; echo '0 0 1 * * certbot renew --nginx --force-renewal --non-interactive --post-hook "nginx -s reload" > /dev/null 2>&1;') | crontab -
            echo ""
            echo -e "${PURPLE}Certificate and Key saved at:${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${CYAN}/etc/letsencrypt/live/$domain/fullchain.pem${NC}"
            echo -e "${CYAN}/etc/letsencrypt/live/$domain/privkey.pem${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${CYAN}ðŸŒŸ N R P installed Successfully.ðŸŒŸ${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        else
            echo ""
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${RED}âŒN R P installation failed.âŒ${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        fi
    }

    # Change Paths
    change_path() {
        if systemctl is-active --quiet nginx && [ -f "/etc/nginx/sites-available/$saved_domain" ]; then
            
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            read -p "Enter the new GRPC path (Service Name) [default: grpc]: " new_grpc_path
            new_grpc_path=${new_grpc_path:-grpc}
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            read -p "Enter the new WebSocket path (Service Name) [default: ws]: " new_ws_path
            new_ws_path=${new_ws_path:-ws}
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            
            sed -i "14s|location ~ .* {$|location ~ ^/${new_grpc_path}/(?<port>\\\d+)/(.*)$ {|" /etc/nginx/sites-available/$saved_domain
            sed -i "28s|location ~ .* {$|location ~ ^/${new_ws_path}/(?<port>\\\d+)$ {|" /etc/nginx/sites-available/$saved_domain
            
            # Restart Nginx
            systemctl restart nginx
            echo -e " ${PURPLE}Paths Changed Successfully${CYAN}:
|-----------------|-------|
| GRPC Path       | ${YELLOW}$new_grpc_path
${CYAN}| WebSocket Path  | ${YELLOW}$new_ws_path  ${CYAN}
|-----------------|-------|${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        else
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${RED}N R P is not installed.${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        fi
    }

    # Install random site
    install_random_fake_site() {
        if [ ! -d "/etc/letsencrypt/live/$saved_domain" ]; then
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${RED}Nginx is not installed.${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            exit 1
        fi

        if [ ! -d "/var/www/html" ]; then
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${RED}/var/www/html does not exist.${NC}"
            exit 1
        fi

        if [ ! -d "/var/www/website-templates" ]; then
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${YELLOW}Downloading Websites list...${NC}"
            sudo git clone https://github.com/learning-zone/website-templates.git /var/www/website-templates
        fi
        
        cd /var/www/website-templates
        sudo rm -rf /var/www/html/*
        random_folder=$(ls -d */ | shuf -n 1)
        sudo mv "$random_folder"/* /var/www/html
        echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        echo -e "${GREEN}Website Installed Successfully${NC}"
        echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
    }

    # Limitation
    add_limit() {
        # Check if NGINX service is installed
        if [ ! -d "/etc/letsencrypt/live/$saved_domain" ]; then
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${RED}N R P is not installed.${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            exit 1
        fi
        
        total_usage(){
            interface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | head -n 1) > /dev/null 2>&1
            data=$(grep "$interface:" /proc/net/dev)
            download=$(echo "$data" | awk '{print $2}')
            upload=$(echo "$data" | awk '{print $10}')
            total_mb=$(echo "scale=2; ($download + $upload) / 1024 / 1024" | bc)
            echo -e "${CYAN}T${YELLOW}o${CYAN}t${YELLOW}a${CYAN}l${YELLOW} U${CYAN}s${YELLOW}a${CYAN}g${YELLOW}e${CYAN}: ${PURPLE}[$total_mb] ${CYAN}MB${NC}"
        }

        echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        echo -e "${YELLOW}* ${CYAN}This option adds a traffic limit to monitor increases in traffic compared to the last 24 hours.${YELLOW}*${NC}"
        echo ""
        echo -e "${YELLOW}* ${CYAN}If the traffic exceeds this limit, the nginx service will be stopped.${YELLOW}*${NC}"
        echo ""
        total_usage
        echo -e "${YELLOW}* ${CYAN}[${YELLOW}Note${CYAN}]: ${CYAN}After restarting the server, the ${CYAN}T${YELLOW}o${CYAN}t${YELLOW}a${CYAN}l${YELLOW} U${CYAN}s${YELLOW}a${CYAN}g${YELLOW}e${CYAN} will also be reset.${YELLOW}*${NC}"
        echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        read -p "Enter the percentage limit [default: 50]: " percentage_limit
        percentage_limit=${percentage_limit:-50}
        echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        if [ ! -d "/root/usage" ]; then
            mkdir -p /root/usage
        fi
        
        cat <<EOL > /root/usage/limit.sh
#!/bin/bash

# Define the interface
interface=\$(ip -o link show | awk -F': ' '{print \$2}' | grep -v "lo" | head -n 1)

# Current total traffic data
get_total(){
    data=\$(grep "\$interface:" /proc/net/dev)
    download=\$(echo "\$data" | awk '{print \$2}')
    upload=\$(echo "\$data" | awk '{print \$10}')
    total_mb=\$(echo "scale=2; (\$download + \$upload) / 1024 / 1024" | bc)
    echo "\$total_mb"
}

# Check traffic increase
check_traffic_increase() {
    current_total_mb=\$(get_total)

    # Check if file exists
    if [ -f "/root/usage/\${interface}_traffic.txt" ]; then
        # Read the traffic data from file
        read -r prev_total_mb < "/root/usage/\${interface}_traffic.txt"

        # Calculate traffic increase percentage
        increase=\$(echo "scale=2; (\$current_total_mb - \$prev_total_mb) / \$prev_total_mb * 100" | bc)
        # Display message if traffic increase is greater than \$percentage_limit%
        if (( \$(echo "\$increase > $percentage_limit" | bc) )); then
            sudo systemctl stop nginx
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] Traffic on interface \$interface increased by more than $percentage_limit% compared to previous:" >> /root/usage/log.txt
        fi
    fi

    # Save current traffic data to file
    echo "\$current_total_mb" > "/root/usage/\${interface}_traffic.txt"
}

check_traffic_increase
EOL

        # Set execute permission for the created script
        chmod +x /root/usage/limit.sh && /root/usage/limit.sh

        # Schedule the script to run every 24 hours using cron job
        (crontab -l 2>/dev/null | grep -v '/root/usage/limit.sh' ; echo '0 0 * * * /root/usage/limit.sh > /dev/null 2>&1;') | crontab -
    }

    # Change port
    change_port() {
        if [ -f "/etc/nginx/sites-available/$saved_domain" ]; then
            current_port=$(grep -oP "listen \[::\]:\K\d+" "/etc/nginx/sites-available/$saved_domain" | head -1)
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${CYAN}Current HTTPS port: ${PURPLE}$current_port${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            read -p "Enter the new HTTPS port [default: 443]: " new_port
            new_port=${new_port:-443}
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            # Change the port in NGINX configuration file
            sed -i "s/listen \[::\]:$current_port ssl http2 ipv6only=on;/listen [::]:$new_port ssl http2 ipv6only=on;/g" "/etc/nginx/sites-available/$saved_domain"
            sed -i "s/listen $current_port ssl http2;/listen $new_port ssl http2;/g" "/etc/nginx/sites-available/$saved_domain"
            
            # Restart NGINX service
            systemctl restart nginx

            # Check if NGINX restarted successfully
            if systemctl is-active --quiet nginx; then
                echo -e "${GREEN}âœ… HTTPS port changed successfully to ${PURPLE}$new_port${NC}"
            else
                echo -e "${RED}âŒ Error: NGINX failed to restart.${NC}"
            fi
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        else
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${RED}N R P is not installed.${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"   
        fi
    }

    # Uninstall N R P
    uninstall() {
        # Check if NGINX is installed
        if [ ! -d "/etc/letsencrypt/live/$saved_domain" ]; then
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${RED}N R P is not installed.${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        else
            echo -e "${GREEN}Uninstalling... ${NC}"
            # Remove SSL certificate files
            rm -rf /etc/letsencrypt > /dev/null 2>&1
            rm -rf /var/www/html/* > /dev/null 2>&1
        
            # Remove NGINX configuration files
            find /etc/nginx/sites-available/ -mindepth 1 -maxdepth 1 ! -name 'default' -exec rm -rf {} +
            find /etc/nginx/sites-enabled/ -mindepth 1 -maxdepth 1 ! -name 'default' -exec rm -rf {} +
        
            # Restart NGINX service
            systemctl restart nginx
            
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
            echo -e "${GREEN}N R P uninstalled successfully.${NC}"
            echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
        fi
    }

    # Main menu
    while true; do
        echo -e "${CYAN}originaly from visit for info   --> Peyman * Github.com/Ptechgithub * ${NC}"
        echo ""
        if systemctl is-active --quiet nginx && [ -f "/etc/nginx/sites-available/$saved_domain" ] > /dev/null 2>&1; then
            echo -e "${GREEN} ðŸŒ Service Installed.${NC}"
        else
            echo -e "${RED}ðŸŒService Not installed${NC}"
        fi
        echo -e "${PURPLE}***********************${NC}"
        echo -e "${YELLOW}* ${CYAN}N${GREEN}ginx ${CYAN}R${GREEN}everse ${CYAN}P${GREEN}roxy${YELLOW} *${NC}"
        echo -e "${PURPLE}***********************${NC}"
        echo -e "${YELLOW} 1) ${GREEN}Install           ${PURPLE}*${NC}"
        echo -e "${PURPLE}                      * ${NC}"
        echo -e "${YELLOW} 2) ${GREEN}Change Paths${NC}      ${PURPLE}*${NC}"
        echo -e "${PURPLE}                      * ${NC}"
        echo -e "${YELLOW} 3) ${GREEN}Change Https Port${NC} ${PURPLE}*${NC}"
        echo -e "${PURPLE}                      * ${NC}"
        echo -e "${YELLOW} 4) ${GREEN}Install Fake Site${NC} ${PURPLE}*${NC}"
        echo -e "${PURPLE}                      * ${NC}"
        echo -e "${YELLOW} 5) ${GREEN}Add Traffic Limit${NC} ${PURPLE}*${NC}"
        echo -e "${PURPLE}                      * ${NC}"
        echo -e "${YELLOW} 6) ${GREEN}Uninstall${NC}         ${PURPLE}*${NC}"
        echo -e "${PURPLE}                      * ${NC}"
        echo -e "${YELLOW} 0) ${PURPLE}Exit${NC}${PURPLE}              *${NC}"
        echo -e "${PURPLE}***********************${NC}"
        read -p "Enter your choice: " choice
        case "$choice" in
            1)
                install
                ;;
            2)
                change_path
                ;;
            3)
                change_port
                ;;
            4)
                install_random_fake_site
                ;;
            5)
                add_limit
                ;;
            6)
                uninstall
                ;;
            0)
                echo -e "${CYAN}By ðŸ–${NC}"
                exit
                ;;
            *)
                echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
                echo "Invalid choice. Please select a valid option."
                echo -e "${YELLOW}Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—Ã—${NC}"
                ;;
        esac
    done
}

### Tor Menu ###

tor_menu() {
    while true; do
        clear
        echo -e "${BLUE}=============================${NC}"
        echo -e "${YELLOW}        Tor Menu             ${NC}"
        echo -e "${BLUE}=============================${NC}"
        echo -e "${GREEN}1.${NC} Install Tor"
        echo -e "${GREEN}2.${NC} Set Tor to use specific country"
        echo -e "${GREEN}3.${NC} Change Tor SOCKS port (default 9050)"
        echo -e "${GREEN}4.${NC} Harden Tor with firewall rules"
        echo -e "${GREEN}5.${NC} Setup Hidden Service for 3x-ui"
        echo -e "${GREEN}6.${NC} Uninstall Tor completely"
        echo -e "${GREEN}7.${NC} Back to Main Menu"
        echo -e "${BLUE}=============================${NC}"
        read -rp "Choose an option: " choice

        case "$choice" in
            1)
                echo "Installing Tor..."
                if ! command -v tor >/dev/null 2>&1; then
                    apt update && apt install -y tor || echo "Failed to install Tor"
                    systemctl enable tor && systemctl start tor
                    echo "Tor installed and started."
                else
                    echo "Tor is already installed."
                fi
                read -rp "Press Enter to continue...";;

            2)
                read -rp "Enter country code (e.g., {ir} for Iran, {de} for Germany): " country
                torrc="/etc/tor/torrc"
                sed -i '/^ExitNodes/d' "$torrc"
                sed -i '/^StrictNodes/d' "$torrc"
                echo "ExitNodes $country" >> "$torrc"
                echo "StrictNodes 1" >> "$torrc"
                systemctl restart tor && echo "Tor now set to use exit country $country"
                read -rp "Press Enter to continue...";;

            3)
                read -rp "Enter new SOCKS port (default is 9050): " newport
                torrc="/etc/tor/torrc"
                sed -i '/^SocksPort/d' "$torrc"
                echo "SocksPort 127.0.0.1:$newport" >> "$torrc"
                systemctl restart tor && echo "SOCKS port changed to $newport"
                read -rp "Press Enter to continue...";;

            4)
                echo "Applying firewall rules to restrict outbound only via Tor..."
                iptables -F
                iptables -A OUTPUT -m owner --uid-owner debian-tor -j ACCEPT
                iptables -A OUTPUT -d 127.0.0.1/32 -j ACCEPT
                iptables -A OUTPUT -j REJECT
                echo "Firewall hardened for Tor."
                read -rp "Press Enter to continue...";;

            5)
                echo "Setting up Hidden Service for 3x-ui on port 54321 (example)..."
                torrc="/etc/tor/torrc"
                hidden_dir="/var/lib/tor/3xui_onion"
                mkdir -p "$hidden_dir"
                chown -R debian-tor:debian-tor "$hidden_dir"
                echo "HiddenServiceDir $hidden_dir" >> "$torrc"
                echo "HiddenServicePort 54321 127.0.0.1:54321" >> "$torrc"
                systemctl restart tor
                sleep 2
                if [[ -f "$hidden_dir/hostname" ]]; then
                    onion_address=$(cat "$hidden_dir/hostname")
                    echo -e "Your hidden service is available at: ${YELLOW}$onion_address${NC}"
                else
                    echo -e "${RED}Failed to retrieve hidden service address.${NC}"
                fi
                read -rp "Press Enter to continue...";;

            6)
                echo "Uninstalling Tor..."
                systemctl stop tor
                systemctl disable tor
                apt purge -y tor
                apt autoremove -y
                rm -rf /etc/tor /var/lib/tor
                echo "Tor uninstalled."
                read -rp "Press Enter to continue...";;

            7)
                break;;

            *)
                echo -e "${RED}Invalid option. Try again.${NC}"
                sleep 1;;
        esac
    done
}

# Function: Install Psiphon with systemd and tweaks
psiphon_management() {
    PSIPHON_DIR="/usr/local/psiphon"
    CONFIG_FILE="$PSIPHON_DIR/psiphon.config"
    SERVICE_FILE="/etc/systemd/system/psiphon.service"
    XUI_CONFIG_DIR="/etc/x-ui"
    LOG_FILE="/var/log/psiphon.log"

    # Full uninstall with cleanup
    uninstall_psiphon() {
        echo -e "${RED}╔════════════════════════════════════╗${NC}"
        echo -e "${RED}║ [!] FULL UNINSTALL IN PROGRESS... ║${NC}"
        echo -e "${RED}╚════════════════════════════════════╝${NC}"
        
        # Stop and disable service
        sudo systemctl stop psiphon 2>/dev/null && echo -e "${YELLOW}[+] Service stopped${NC}"
        sudo systemctl disable psiphon 2>/dev/null && echo -e "${YELLOW}[+] Service disabled${NC}"
        sudo rm -f "$SERVICE_FILE" && echo -e "${YELLOW}[+] Service file removed${NC}"
        sudo systemctl daemon-reload

        # Remove 3X-UI outbound configuration
        if [ -f "$XUI_CONFIG_DIR/config.json" ]; then
            echo -e "${YELLOW}[+] Removing from 3X-UI config...${NC}"
            sudo jq 'del(.outbounds[] | select(.tag == "psiphon-outbound"))' \
                "$XUI_CONFIG_DIR/config.json" > "$XUI_CONFIG_DIR/config.tmp" \
                && sudo mv "$XUI_CONFIG_DIR/config.tmp" "$XUI_CONFIG_DIR/config.json" \
                && echo -e "${GREEN}[✓] 3X-UI config cleaned${NC}"
        fi

        # Clean files
        sudo rm -rf "$PSIPHON_DIR" && echo -e "${YELLOW}[+] Psiphon directory removed${NC}"
        sudo rm -f "$LOG_FILE" && echo -e "${YELLOW}[+] Logs cleared${NC}"
        
        echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║ [✓] PSIPHON COMPLETELY REMOVED     ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
    }

    # Install dependencies
    install_deps() {
        echo -e "${BLUE}╔════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║ [+] INSTALLING DEPENDENCIES...    ║${NC}"
        echo -e "${BLUE}╚════════════════════════════════════╝${NC}"
        sudo apt update && sudo apt install -y wget unzip python3 python3-pip jq \
        && pip3 install --upgrade pip || handle_error "Dependency installation failed"
        echo -e "${GREEN}[✓] Dependencies installed${NC}"
    }

    # Main installation
    install_psiphon() {
        install_deps
        
        echo -e "${BLUE}╔════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║ [+] INSTALLING PSIPHON...         ║${NC}"
        echo -e "${BLUE}╚════════════════════════════════════╝${NC}"
        
        sudo mkdir -p "$PSIPHON_DIR" || handle_error "Failed to create directory"
        cd "$PSIPHON_DIR" || handle_error "Failed to enter directory"

        # Download and extract
        echo -e "${YELLOW}[+] Downloading Psiphon client...${NC}"
        wget -q --https-only https://psiphon.ca/psiphon3.zip -O psiphon3.zip \
        && unzip -q psiphon3.zip \
        && rm -f psiphon3.zip || handle_error "Download/extraction failed"
        echo -e "${GREEN}[✓] Psiphon package installed${NC}"

        # Create config
        sudo bash -c "cat > '$CONFIG_FILE'" << 'EOL'
{
    "PropagationChannelId": "DEFAULT",
    "SponsorId": "DEFAULT",
    "UseIndistinguishableTLS": true,
    "TunnelWholeDevice": true,
    "AllowTCPPorts": {"80": "HTTP-ROOT", "443": "HTTPS-ROOT"}
}
EOL
        echo -e "${GREEN}[✓] Configuration file created${NC}"

        # Create systemd service
        sudo bash -c "cat > '$SERVICE_FILE'" << EOL
[Unit]
Description=Psiphon Client
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PSIPHON_DIR
ExecStart=/usr/bin/python3 $PSIPHON_DIR/psiphon-tunnel-core.py -config $CONFIG_FILE
Restart=on-failure
RestartSec=5s
StandardOutput=file:$LOG_FILE
StandardError=file:$LOG_FILE

[Install]
WantedBy=multi-user.target
EOL
        echo -e "${GREEN}[✓] Systemd service configured${NC}"

        # Configure 3X-UI outbound
        if [ -d "$XUI_CONFIG_DIR" ]; then
            echo -e "${YELLOW}[+] Configuring 3X-UI outbound...${NC}"
            if ! grep -q "psiphon-outbound" "$XUI_CONFIG_DIR/config.json"; then
                sudo jq '.outbounds += [{
                    "protocol": "socks",
                    "settings": {
                        "servers": [{
                            "address": "127.0.0.1",
                            "port": 1080,
                            "users": []
                        }]
                    },
                    "tag": "psiphon-outbound"
                }]' "$XUI_CONFIG_DIR/config.json" > "$XUI_CONFIG_DIR/config.tmp" \
                && sudo mv "$XUI_CONFIG_DIR/config.tmp" "$XUI_CONFIG_DIR/config.json" \
                && echo -e "${GREEN}[✓] 3X-UI integration complete${NC}"
            else
                echo -e "${YELLOW}[!] Psiphon outbound already exists in 3X-UI config${NC}"
            fi
        fi

        sudo systemctl daemon-reload
        echo -e "${GREEN}╔════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║ [✓] INSTALLATION COMPLETE          ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════╝${NC}"
        echo -e "Edit config: ${CYAN}$CONFIG_FILE${NC}"
    }

    # Service control functions
    start_psiphon() {
        echo -e "${YELLOW}[+] Starting Psiphon service...${NC}"
        sudo systemctl start psiphon \
        && echo -e "${GREEN}[✓] Service started${NC}" \
        || handle_error "Start failed"
    }

    stop_psiphon() {
        echo -e "${YELLOW}[!] Stopping Psiphon service...${NC}"
        sudo systemctl stop psiphon \
        && echo -e "${GREEN}[✓] Service stopped${NC}" \
        || handle_error "Stop failed"
    }

    # Main menu
    while true; do
        echo -e "\n${CYAN}╔════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║ ${CYAN}PSIPHON MANAGER ${CYAN}(3X-UI Integrated) ║${NC}"
        echo -e "${BLUE}╚════════════════════════════════════╝${NC}"
        echo -e "${LGREEN}1) ${CYAN}Install/Reinstall${NC}"
        echo -e "${LGREEN}2) ${GREEN}Start Service${NC}"
        echo -e "${LGREEN}3) ${YELLOW}Stop Service${NC}"
        echo -e "${LGREEN}4) ${CYAN}Check Status${NC}"
        echo -e "${LGREEN}5) ${CYAN}View Logs${NC}"
        echo -e "${LGREEN}6) ${YELLOW}Full Uninstall${NC}"
        echo -e "${LGREEN}0) ${YELLOW}Back to Main Menu${NC}"
        echo -e "${PURPLE}╔════════════════════════════════════╗${NC}"
        read -p "$(echo -e "${CYAN}Choose option: ${NC}")" choice

        case $choice in
            1) install_psiphon ;;
            2) start_psiphon ;;
            3) stop_psiphon ;;
            4) echo -e "${BLUE}"; sudo systemctl status psiphon -l; echo -e "${NC}" ;;
            5) echo -e "${CYAN}"; [ -f "$LOG_FILE" ] && sudo tail -n 20 "$LOG_FILE" || echo "No logs found"; echo -e "${NC}" ;;
            6) uninstall_psiphon ;;
            0) break ;;
            *) echo -e "${RED}Invalid choice!${NC}" ;;
        esac
    done
}

### Random HTML Site ###

random_template_site() {
    # Check for dependencies
    if ! command -v wget >/dev/null || ! command -v unzip >/dev/null || ! command -v shuf >/dev/null; then
        echo -e "${RED}Required commands (wget, unzip, shuf) not found!${NC}"
        exit 1
    fi

    # Download and extract randomfakehtml if not present
    cd "$HOME" || handle_error "Failed to change to HOME directory"

    if [[ ! -d "randomfakehtml-master" ]]; then
        echo -e "${YELLOW}Downloading randomfakehtml template...${NC}"
        wget -q https://github.com/GFW4Fun/randomfakehtml/archive/refs/heads/master.zip || handle_error "Failed to download randomfakehtml"
        unzip -q master.zip && rm -f master.zip || handle_error "Failed to unzip randomfakehtml"
    fi

    cd randomfakehtml-master || handle_error "Failed to change to randomfakehtml-master directory"
    rm -rf assets ".gitattributes" "README.md" "_config.yml" || true

    # Pick a random template directory
    RandomHTML=$(find . -maxdepth 1 -type d ! -name '.' | sed 's|^\./||' | shuf -n1)
    echo -e "${YELLOW}Random template name selected: ${RandomHTML}${NC}"

    # Copy to web directory, but don't delete post.php
    if [[ -d "${RandomHTML}" && -d "/var/www/html/" ]]; then
        echo -e "${YELLOW}Copying template to web directory...${NC}"
        # Remove everything except post.php (files and directories)
        find /var/www/html/ ! -name 'post.php' -type f -exec rm -f {} +
        find /var/www/html/ ! -name 'post.php' -type d -mindepth 1 -exec rm -rf {} +

        cp -a "${RandomHTML}/." /var/www/html/ || handle_error "Failed to copy template files"
        echo -e "${GREEN}Template extracted successfully!${NC}"
        
        echo -e "\n${CYAN}To automate daily random template updates every 6 hours, add the following to your crontab:${NC}"
        echo -e "${YELLOW}sudo crontab -e${NC}"
        echo -e "${YELLOW}Then add this line to the file that opens:${NC}"
        echo -e "${YELLOW}0 */6 * * * /bin/bash $(readlink -f "$0") --random-template >> /var/log/mtproxy-whitelist.log 2>&1${NC}"
        echo -e "${YELLOW}(This will update the template at 00:00, 06:00, 12:00, and 18:00 daily.)${NC}"
    else
        handle_error "Extraction error: Template directory not found or web directory missing."
    fi
}

### Main Menu ###

main_menu() {
    while true; do
        echo -e "\n${LGREEN}===== Main Menu =====${NC}"
        echo "1) Update System"
        echo "2) Install Utilities"
        echo "3) Install Nginx"
        echo "4) Manage Nginx"
        echo "5) Configure Nginx Wildcard SSL"
        echo "6) Install x-ui"
        echo "7) Reality-EZ Menu"
        echo "8) Install Hiddify Panel"
        echo "9) Install Telegram MTProto Proxy"
        echo "10) Install OpenVPN and Stunnel"
        echo "11) Install fail2ban"
        echo "12) Create Swap File"
        echo "13) Change SSH port"
        echo "14) Schedule system reboot every 2 days"
        echo "15) Uninstall Nginx"
        echo "16) Install Random Template Site"
        echo "17) Tor Installation"
        echo "18) Psiphone+3x-ui (binding) Installer"
        echo "19) Nginx Reverse Proxy Setup"
        echo "20) Manage Functions"
        
        echo "0) Exit"
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
            16) random_template_site ;;
            17) tor_menu ;;
            18) psiphon_management ;;
            19) nginx_reverseProxy ;;
            20) manage_functions ;;
            
            0) 
                echo -e "${GREEN}Exiting...${NC}"
                exit 0 ;;
            *)
                echo -e "${RED}Invalid choice!${NC}" ;;
        esac
    done
}

# Start the script
if [[ "$#" -eq 1 && "$1" == "--random-template" ]]; then
    random_template_site
    exit 0
fi

check_root
main_menu
