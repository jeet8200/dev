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
###
#adding or removing functions to/from the list 

# Function to list all available functions in this script
list_functions() {
    echo "Available functions:"
    grep -E '^[a-zA-Z0-9_]+\(\)' "$0" | awk -F '(' '{print NR ") " $1}'
}

# Function to add a new function to this script
add_function() {
    read -p "Enter the function name to add: " func_name

    # Check if function already exists
    if grep -q "^$func_name()" "$0"; then
        echo "Function '$func_name' already exists!"
        return
    fi

    echo "Enter the function code (end with an empty line):"
    func_code=""
    while IFS= read -r line; do
        [[ -z "$line" ]] && break
        func_code+="$line"$'\n'
    done

    # Append the function to the script
    echo -e "\n$func_name() {\n$func_code\n}" >> "$0"
    echo "Function '$func_name' added successfully!"

    # Make sure the script remains executable
    chmod +x "$0"
}

# Function to remove an existing function
remove_function() {
    list_functions
    read -p "Enter the function name to remove: " func_name

    # Check if function exists
    if ! grep -q "^$func_name()" "$0"; then
        echo "Function '$func_name' does not exist!"
        return
    fi

    # Remove the function
    sed -i "/^$func_name()/,/^}/d" "$0"
    echo "Function '$func_name' removed successfully!"
}

# Function to manage menu items (add/remove functions)
manage_functions() {
    while true; do
        echo -e "\nManage Functions Menu:"
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
            *) echo "Invalid choice! Please try again." ;;
        esac
    done
}


# Function to update the package lists, upgrade installed packages, and clean up
update_system() {
    if sudo apt update -y && sudo apt upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y sh -c 'apt-get update; apt-get upgrade -y; apt-get dist-upgrade -y; apt-get autoremove -y; apt-get autoclean -y'; then
        echo -e "${GREEN}System update completed successfully.${NC}"
    else
        handle_error "Failed to update system."
    fi
}

# Function to install sudo and wget
install_utilities() {
    if sudo apt install && sudo apt install ufw -y sudo wget apt-get install -y software-properties-common ufw wget curl git socat cron busybox bash-completion locales nano apt-utils  ; then
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
nginx_reverseProxy(){
#!/bin/bash

#colors
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
purple='\033[0;35m'
cyan='\033[0;36m'
rest='\033[0m'

# Check for root user
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

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
            echo -e "${yellow}${dep} is not installed. Installing...${rest}"
            sudo "${p_m}" install "${dep}" -y
        fi
    done
}

# Display error and exit
display_error() {
  echo -e "${red}Error: $1${rest}"
  exit 1
}

# Store domain name
d_f="/etc/nginx/d.txt"
# Read domain from file
saved_domain=$(cat "$d_f" 2>/dev/null)


# Install Reverse nginx
install() {
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

# Check installation statu
check_status() {
	if systemctl is-active --quiet nginx && [ -f "/etc/nginx/sites-available/$saved_domain" ] > /dev/null 2>&1; then
	  echo -e "${green} 🌐 Service Installed.${rest}"
	else
	  echo -e "${red}🌐Service Not installed${rest}"
	fi
}

# Function to check installation status
check_installation() {
  if systemctl is-active --quiet nginx && [ -f "/etc/nginx/sites-available/$domain" ]; then
    (crontab -l 2>/dev/null | grep -v 'certbot renew --nginx --force-renewal --non-interactive --post-hook "nginx -s reload"' ; echo '0 0 1 * * certbot renew --nginx --force-renewal --non-interactive --post-hook "nginx -s reload" > /dev/null 2>&1;') | crontab -
    echo ""
    echo -e "${purple}Certificate and Key saved at:${rest}"
    echo -e "${yellow}×××××××××××××××××××××××××××××××××××××××××××××××××××××${rest}"
    echo -e "${cyan}/etc/letsencrypt/live/$domain/fullchain.pem${rest}"
    echo -e "${cyan}/etc/letsencrypt/live/$domain/privkey.pem${rest}"
    echo -e "${yellow}×××××××××××××××××××××××××××××××××××××××××××××××××××××${rest}"
    echo -e "${cyan}🌟 N R P installed Successfully.🌟${rest}"
    echo -e "${yellow}××××××××××××××××××××××××××××××××${rest}"
  else
    echo ""
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
    echo -e "${red}❌N R P installation failed.❌${rest}"
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
  fi
}

# Change Paths
change_path() {
  if systemctl is-active --quiet nginx && [ -f "/etc/nginx/sites-available/$saved_domain" ]; then
     
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
    read -p "Enter the new GRPC path (Service Name) [default: grpc]: " new_grpc_path
    new_grpc_path=${new_grpc_path:-grpc}
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
    read -p "Enter the new WebSocket path (Service Name) [default: ws]: " new_ws_path
    new_ws_path=${new_ws_path:-ws}
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
    
    sed -i "14s|location ~ .* {$|location ~ ^/${new_grpc_path}/(?<port>\\\d+)/(.*)$ {|" /etc/nginx/sites-available/$saved_domain
    sed -i "28s|location ~ .* {$|location ~ ^/${new_ws_path}/(?<port>\\\d+)$ {|" /etc/nginx/sites-available/$saved_domain
    
    # Restart Nginx
    systemctl restart nginx
    echo -e " ${purple}Paths Changed Successfully${cyan}:
|-----------------|-------|
| GRPC Path       | ${yellow}$new_grpc_path
${cyan}| WebSocket Path  | ${yellow}$new_ws_path  ${cyan}
|-----------------|-------|${rest}"
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
  else
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
    echo -e "${red}N R P is not installed.${rest}"
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
  fi
}

# Install random site
install_random_fake_site() {
    if [ ! -d "/etc/letsencrypt/live/$saved_domain" ]; then
        echo -e "${yellow}×××××××××××××××××××××××${rest}"
        echo -e "${red}Nginx is not installed.${rest}"
        echo -e "${yellow}×××××××××××××××××××××××${rest}"
        exit 1
    fi

    if [ ! -d "/var/www/html" ]; then
        echo -e "${yellow}×××××××××××××××××××××××${rest}"
        echo -e "${red}/var/www/html does not exist.${rest}"
        exit 1
    fi

    if [ ! -d "/var/www/website-templates" ]; then
        echo -e "${yellow}×××××××××××××××××××××××${rest}"
        echo -e "${yellow}Downloading Websites list...${rest}"
        sudo git clone https://github.com/learning-zone/website-templates.git /var/www/website-templates
    fi
    
    cd /var/www/website-templates
    sudo rm -rf /var/www/html/*
    random_folder=$(ls -d */ | shuf -n 1)
    sudo mv "$random_folder"/* /var/www/html
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
    echo -e "${green}Website Installed Successfully${rest}"
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
}
#managing menu
# Function to manage menu items (add/remove)
manage_menu_items() {
    echo "1) List functions"
    echo "2) Add function"
    echo "3) Remove function"
    echo "4) Exit"
    read -p "Choose an option: " choice

    case $choice in
        1) list_functions ;;
        2) add_function ;;
        3) remove_function ;;
        4) return ;;
        *) echo "Invalid choice!";;
    esac
}


# Limitation
add_limit() {
    # Check if NGINX service is installed
    if [ ! -d "/etc/letsencrypt/live/$saved_domain" ]; then
        echo -e "${yellow}×××××××××××××××××××××××${rest}"
        echo -e "${red}N R P is not installed.${rest}"
        echo -e "${yellow}×××××××××××××××××××××××${rest}"
        exit 1
    fi
    
total_usage(){
    interface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | head -n 1) > /dev/null 2>&1
    data=$(grep "$interface:" /proc/net/dev)
    download=$(echo "$data" | awk '{print $2}')
    upload=$(echo "$data" | awk '{print $10}')
    total_mb=$(echo "scale=2; ($download + $upload) / 1024 / 1024" | bc)
    echo -e "${cyan}T${yellow}o${cyan}t${yellow}a${cyan}l${yellow} U${cyan}s${yellow}a${cyan}g${yellow}e${cyan}: ${purple}[$total_mb] ${cyan}MB${rest}"
}

    echo -e "${yellow}×××××××××××××××××××××××${rest}"
    echo -e "${yellow}* ${cyan}This option adds a traffic limit to monitor increases in traffic compared to the last 24 hours.${yellow}*${rest}"
    echo ""
    echo -e "${yellow}* ${cyan}If the traffic exceeds this limit, the nginx service will be stopped.${yellow}*${rest}"
    echo ""
    total_usage
    echo -e "${yellow}* ${cyan}[${yellow}Note${cyan}]: ${cyan}After restarting the server, the ${cyan}T${yellow}o${cyan}t${yellow}a${cyan}l${yellow} U${cyan}s${yellow}a${cyan}g${yellow}e${cyan} will also be reset.${yellow}*${rest}"
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
    read -p "Enter the percentage limit [default: 50]: " percentage_limit
    percentage_limit=${percentage_limit:-50}
    echo -e "${yellow}×××××××××××××××××××××××${rest}"

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

#--------------

# Change port
change_port() {
    if [ -f "/etc/nginx/sites-available/$saved_domain" ]; then
        current_port=$(grep -oP "listen \[::\]:\K\d+" "/etc/nginx/sites-available/$saved_domain" | head -1)
        echo -e "${yellow}×××××××××××××××××××××××${rest}"
        echo -e "${cyan}Current HTTPS port: ${purple}$current_port${rest}"
        echo -e "${yellow}×××××××××××××××××××××××${rest}"
        read -p "Enter the new HTTPS port [default: 443]: " new_port
        new_port=${new_port:-443}
        echo -e "${yellow}×××××××××××××××××××××××${rest}"

        # Change the port in NGINX configuration file
        sed -i "s/listen \[::\]:$current_port ssl http2 ipv6only=on;/listen [::]:$new_port ssl http2 ipv6only=on;/g" "/etc/nginx/sites-available/$saved_domain"
        sed -i "s/listen $current_port ssl http2;/listen $new_port ssl http2;/g" "/etc/nginx/sites-available/$saved_domain"
        
        # Restart NGINX service
        systemctl restart nginx

        # Check if NGINX restarted successfully
        if systemctl is-active --quiet nginx; then
            echo -e "${green}✅ HTTPS port changed successfully to ${purple}$new_port${rest}"
        else
            echo -e "${red}❌ Error: NGINX failed to restart.${rest}"
        fi
        echo -e "${yellow}×××××××××××××××××××××××${rest}"
    else
        echo -e "${yellow}×××××××××××××××××××××××××××××××××××${rest}"
        echo -e "${red}N R P is not installed.${rest}"
        echo -e "${yellow}×××××××××××××××××××××××××××××××××××${rest}"
    fi
}

# Uninstall N R P
uninstall() {
  # Check if NGINX is installed
  if [ ! -d "/etc/letsencrypt/live/$saved_domain" ]; then
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
    echo -e "${red}N R P is not installed.${rest}"
    echo -e "${yellow}×××××××××××××××××××××××${rest}"
  else
      echo -e "${green}☑️Uninstalling... ${rest}"
	  # Remove SSL certificate files
	  rm -rf /etc/letsencrypt > /dev/null 2>&1
	  rm -rf /var/www/html/* > /dev/null 2>&1
	
	  # Remove NGINX configuration files
	  find /etc/nginx/sites-available/ -mindepth 1 -maxdepth 1 ! -name 'default' -exec rm -rf {} +
	  find /etc/nginx/sites-enabled/ -mindepth 1 -maxdepth 1 ! -name 'default' -exec rm -rf {} +
	
	  # Restart NGINX service
	  systemctl restart nginx
	   
	  echo -e "${yellow}××××××××××××××××××××××××××××××${rest}"
	  echo -e "${green}N R P uninstalled successfully.${rest}"
	  echo -e "${yellow}××××××××××××××××××××××××××××××${rest}"
  fi
}

clear
echo -e "${cyan}originaly from visit for info   --> Peyman * Github.com/Ptechgithub * ${rest}"
echo ""
check_status
echo -e "${purple}***********************${rest}"
echo -e "${yellow}* ${cyan}N${green}ginx ${cyan}R${green}everse ${cyan}P${green}roxy${yellow} *${rest}"
echo -e "${purple}***********************${rest}"
echo -e "${yellow} 1) ${green}Install           ${purple}*${rest}"
echo -e "${purple}                      * ${rest}"
echo -e "${yellow} 2) ${green}Change Paths${rest}      ${purple}*${rest}"
echo -e "${purple}                      * ${rest}"
echo -e "${yellow} 3) ${green}Change Https Port${rest} ${purple}*${rest}"
echo -e "${purple}                      * ${rest}"
echo -e "${yellow} 4) ${green}Install Fake Site${rest} ${purple}*${rest}"
echo -e "${purple}                      * ${rest}"
echo -e "${yellow} 5) ${green}Add Traffic Limit${rest} ${purple}*${rest}"
echo -e "${purple}                      * ${rest}"
echo -e "${yellow} 6) ${green}Uninstall${rest}         ${purple}*${rest}"
echo -e "${purple}                      * ${rest}"
echo -e "${yellow} 0) ${purple}Exit${rest}${purple}              *${rest}"
echo -e "${purple}***********************${rest}"
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
        echo -e "${cyan}By 🖐${rest}"
        exit
        ;;
    *)
        echo -e "${yellow}××××××××××××××××××××××××××××××${rest}"
        echo "Invalid choice. Please select a valid option."
        echo -e "${yellow}××××××××××××××××××××××××××××××${rest}"
        ;;
esac

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
        echo -e " ${YELLOW}16.${NC} Nginx reverse proxy setup with path for x-ui v2ray configs TESTING....."
	echo -e " ${YELLOW}17.${NC} Manage Functions"
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
	    16) nginx_reverseProxy;;
	    17) manage_functions;;  # This is the new function
             0) exit 0 ;;
            *) handle_error "Invalid choice. Please enter a number between 0 and 16." ;;
        esac
    done
}

# Start the main menu
main_menu
