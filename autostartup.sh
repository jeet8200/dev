#!/bin/bash

# ==============================================
# MTProto Proxy Whitelist Installer
# Enhanced Version with Security, Error Handling,
# Performance Optimizations, Timestamped Whitelist,
# NGINX Proxy Protocol Support, Automated Cleanup,
# and Telegram User Management (using long Telegram links)
# ==============================================

# Exit immediately if a command exits with a non-zero status.
# Treat unset variables as an error.
# The return value of a pipeline is the value of the last (rightmost) command to exit with a non-zero status, or zero if all commands in the pipeline exit successfully.
set -euo pipefail

# Configuration
CONFIG_FILE="/etc/mtproxy-whitelist.conf"
LOG_FILE="/var/log/mtproxy-whitelist.log"
NGINX_CONF_DIR="/etc/nginx"
WHITE_LIST_FILE="$NGINX_CONF_DIR/whitelist.txt"
PASSWORD_FILE="$NGINX_CONF_DIR/.password"
USED_TOKENS_FILE="$NGINX_CONF_DIR/used_tokens.txt" # Used for one-time tokens
WEB_DIR="/var/www/html"
NGINX_STREAM_CONF="$NGINX_CONF_DIR/nginx.conf"
NGINX_SITES_DIR="$NGINX_CONF_DIR/sites-available"
NGINX_SITES_LINK="$NGINX_CONF_DIR/sites-enabled/whitelist_gateway"
WHITELIST_SITE_CONF="$NGINX_SITES_DIR/whitelist_gateway"
STREAM_CONF_FILE="$NGINX_CONF_DIR/stream.d/mtproto.conf"
BACKUP_DIR="/var/backups/mtproxy-whitelist"
TELEGRAM_USERS_FILE="$NGINX_CONF_DIR/telegram_users.txt" # File to store Telegram users (username:chat_id:proxy_address)
TELEGRAM_BOT_TOKEN_FILE="$NGINX_CONF_DIR/mtproxy-whitelist.conf.telegram_token" # File to store Telegram Bot Token

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m' # Add this line
NC='\033[0m' # No Color

# Initialize variables
DOMAIN=""
PROXY_PORT=""
NGINX_PORT=""
PHP_VERSION=""
TELEGRAM_BOT_TOKEN="" # Variable to hold the loaded token

# ==============================================
# HELPER FUNCTIONS
# ==============================================

# Logging function
log() {
  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Error handling function
error_exit() {
  log "${RED}ERROR: $1${NC}"
  exit 1
}

# Check if running as root
check_root() {
  if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root. Please use sudo."
  fi
}

# Validate port number
validate_port() {
  local port="$1"
  if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
    error_exit "Invalid port number: $port. Must be between 1-65535."
  fi
}

# Validate domain name
validate_domain() {
  local domain="$1"
  if [[ -z "$domain" ]]; then
    error_exit "Domain cannot be empty."
  fi

  # Simple domain validation regex
  if ! [[ "$domain" =~ ^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$ ]]; then
    error_exit "Invalid domain format: $domain"
  fi
}

# Validate password strength
validate_password() {
  local password="$1"
  if [[ ${#password} -lt 12 ]]; then
    error_exit "Password must be at least 12 characters long."
  fi
}

# Install ufw if missing
install_ufw_if_missing() {
    if ! command -v ufw >/dev/null 2>&1; then
        echo "Installing ufw..."
        apt install ufw -y || error_exit "Failed to install ufw"
    fi
}

# Install unzip if missing
install_unzip_if_missing() {
    if ! command -v unzip >/dev/null 2>&1; then
        echo "Installing unzip..."
        apt install unzip -y || error_exit "Failed to install unzip"
    fi
}

# Install dig (dnsutils) if missing
install_dig_if_missing() {
    if ! command -v dig >/dev/null 2>&1; then
        echo "Installing dnsutils (for dig)..."
        apt install dnsutils -y || error_exit "Failed to install dnsutils"
    fi
}

# Check dependencies
check_dependencies() {
  install_ufw_if_missing
  install_unzip_if_missing
  install_dig_if_missing
  local dependencies=("curl" "openssl" "ufw" "systemctl" "shuf" "dig")
  for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      error_exit "Missing required dependency: $dep"
    fi
  done
}
#wildcard cloudflare cert
cloudflare_cert_menu() {
    local BASE_DIR="$HOME/.cloudflare_certs"
    local LIST_FILE="$BASE_DIR/cert_list.txt"
    mkdir -p "$BASE_DIR"
    touch "$LIST_FILE"

    while true; do
        echo ""
        echo "=== Cloudflare Wildcard SSL Certificate Manager ==="
        echo "1) Add new wildcard certificate"
        echo "2) List managed domains"
        echo "3) Delete a domain's certificate + credentials"
        echo "4) Renew a domain's certificate"
        echo "5) Back to main menu"
        read -rp "Choose an option: " option

        case "$option" in
            1)
                read -rp "Enter your wildcard domain (e.g. *.example.com): " wildcard_domain
                domain=$(echo "$wildcard_domain" | sed 's/\*\.//')
                cred_file="$BASE_DIR/cloudflare_${domain}.ini"

                if grep -q "^$domain:" "$LIST_FILE"; then
                    echo "âš ï¸ Domain $domain already exists."
                    return
                fi

                echo "Choose authentication method:"
                echo "1) Global API Key (requires email)"
                echo "2) API Token (recommended)"
                read -rp "Enter 1 or 2: " auth_choice

                if [[ "$auth_choice" == "1" ]]; then
                    read -rp "Enter your Cloudflare email: " cf_email
                    read -rsp "Enter your Global API Key: " cf_key
                    echo ""
                    cat > "$cred_file" <<EOF
dns_cloudflare_email = $cf_email
dns_cloudflare_api_key = $cf_key
EOF
                    auth_type="api_key"
                elif [[ "$auth_choice" == "2" ]]; then
                    read -rsp "Enter your Cloudflare API Token: " cf_token
                    echo ""
                    cat > "$cred_file" <<EOF
dns_cloudflare_api_token = $cf_token
EOF
                    auth_type="api_token"
                else
                    echo "Invalid choice."
                    continue
                fi

                chmod 600 "$cred_file"
                echo "Requesting certificate for $wildcard_domain and $domain..."
                if sudo certbot certonly \
                    --dns-cloudflare \
                    --dns-cloudflare-credentials "$cred_file" \
                    -d "$wildcard_domain" -d "$domain"; then
                    echo "$domain:$auth_type:$cred_file" >> "$LIST_FILE"
                    echo "âœ… Certificate issued successfully."
                else
                    echo "âŒ Certificate issuance failed."
                fi
                ;;
            2)
                echo "=== Managed Domains ==="
                if [[ ! -s "$LIST_FILE" ]]; then
                    echo "No domains found."
                else
                    nl -w2 -s'. ' "$LIST_FILE" | cut -d':' -f1
                fi
                ;;
            3)
                nl -w2 -s'. ' "$LIST_FILE" | cut -d':' -f1
                read -rp "Enter the domain to delete (e.g. example.com): " domain
                line=$(grep "^$domain:" "$LIST_FILE")
                if [[ -z "$line" ]]; then
                    echo "Domain not found."
                else
                    cred_file=$(echo "$line" | cut -d':' -f3)
                    sudo certbot delete --cert-name "$domain"
                    rm -f "$cred_file"
                    sed -i "/^$domain:/d" "$LIST_FILE"
                    echo "âœ… Deleted $domain and its associated files."
                fi
                ;;
            4)
                nl -w2 -s'. ' "$LIST_FILE" | cut -d':' -f1
                read -rp "Enter the domain to renew (e.g. example.com): " domain
                line=$(grep "^$domain:" "$LIST_FILE")
                if [[ -z "$line" ]]; then
                    echo "Domain not found."
                else
                    cred_file=$(echo "$line" | cut -d':' -f3)
                    sudo certbot certonly \
                        --dns-cloudflare \
                        --dns-cloudflare-credentials "$cred_file" \
                        -d "*.$domain" -d "$domain" || echo "âŒ Renewal failed for $domain."
                fi
                ;;
            5) break ;;
            *) echo "Invalid option." ;;
        esac
    done
}

# Load configuration
load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE" || error_exit "Failed to load config file."
  fi
  # Load Telegram Bot Token if file exists
  if [[ -f "$TELEGRAM_BOT_TOKEN_FILE" ]] && [[ -s "$TELEGRAM_BOT_TOKEN_FILE" ]]; then
      TELEGRAM_BOT_TOKEN=$(cat "$TELEGRAM_BOT_TOKEN_FILE") || error_exit "Failed to read Telegram bot token file."
      log "Loaded existing Telegram bot token."
  fi
}

# Save configuration
save_config() {
  mkdir -p "$(dirname "$CONFIG_FILE")"
  cat > "$CONFIG_FILE" <<EOF
# MTProxy Whitelist Configuration
DOMAIN="$DOMAIN"
PROXY_PORT="$PROXY_PORT"
NGINX_PORT="$NGINX_PORT"
EOF
  chmod 600 "$CONFIG_FILE"
}

# Save Telegram Bot Token
save_telegram_bot_token() {
    local token="$1"
    echo "$token" > "$TELEGRAM_BOT_TOKEN_FILE" || error_exit "Failed to save Telegram bot token."
    chmod 600 "$TELEGRAM_BOT_TOKEN_FILE" || error_exit "Failed to set permissions for Telegram bot token file."
    chown root:root "$TELEGRAM_BOT_TOKEN_FILE" || error_exit "Failed to set ownership for Telegram bot token file."
    log "${GREEN}Telegram bot token saved securely.${NC}"
}

# Create backup
create_backup() {
  log "Creating backup of current configuration..."
  mkdir -p "$BACKUP_DIR"
  local timestamp=$(date +%Y%m%d-%H%M%S)
  local backup_file="$BACKUP_DIR/config-$timestamp.tar.gz"

  # Using || true to prevent script from exiting if some files are missing during backup
  tar -czf "$backup_file" \
    "$WHITE_LIST_FILE" \
    "$PASSWORD_FILE" \
    "$USED_TOKENS_FILE" \
    "$NGINX_CONF_DIR" \
    "$WEB_DIR/post.php" \
    "$TELEGRAM_USERS_FILE" \
    "$TELEGRAM_BOT_TOKEN_FILE" || true

  if [[ $? -eq 0 ]]; then
    log "Backup created: ${GREEN}$backup_file${NC}"
  else
    log "${YELLOW}Warning: Backup creation failed or some files were missing.${NC}"
  fi
}

# Check PHP version
get_php_version() {
  if command -v php >/dev/null 2>&1; then
    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
  else
    PHP_VERSION=""
  fi
}

# Check if domain resolves to this server's public IP
check_domain_resolution() {
    local domain="$1"
    log "Checking if domain '$domain' resolves to this server's IP..."

    local public_ip=$(curl -s ifconfig.me)
    if [[ -z "$public_ip" ]]; then
        error_exit "Could not determine this server's public IP. Check internet connectivity."
    fi

    local resolved_ip=$(dig +short "$domain" | head -n 1)
    if [[ -z "$resolved_ip" ]]; then
        error_exit "Domain '$domain' does not resolve to any IP. Please check your DNS settings."
    fi

    if [[ "$public_ip" != "$resolved_ip" ]]; then
        error_exit "Domain '$domain' resolves to '$resolved_ip', but this server's IP is '$public_ip'. Please update your DNS A record."
    fi
    log "${GREEN}Domain '$domain' successfully resolves to this server's IP.${NC}"
}

# Add Telegram user to file (updated to include proxy_address)
add_telegram_user() {
    local username="$1"
    local chat_id="$2"
    local proxy_address="${3:-}" # Optional proxy_address, default to empty

    # Escape potential colons in username to prevent issues with IFS later
    # This also handles the proxy address being the last field correctly.
    local escaped_username=$(echo "$username" | sed 's/:/\\:/g')

    # Check if user already exists based on escaped username and chat_id
    if grep -q "^${escaped_username}:${chat_id}:" "$TELEGRAM_USERS_FILE" || \
       grep -q "^${escaped_username}:${chat_id}$" "$TELEGRAM_USERS_FILE"; then # Also check old format without proxy
        log "${YELLOW}Telegram user '${username}' with chat ID '${chat_id}' already exists. Updating entry.${NC}"
        # Update existing entry by deleting and re-adding
        # Use awk to find the line and replace, ensuring the new line is correctly formatted
        # This is safer than sed -i /c\ for handling potential colons in old/new proxy address
        awk -v old_user="${escaped_username}" -v old_chat="${chat_id}" -v new_line="${escaped_username}:${chat_id}:${proxy_address}" '
            BEGIN { found = 0 }
            $0 ~ "^" old_user ":" old_chat "(:|$)" {
                print new_line
                found = 1
            }
            !($0 ~ "^" old_user ":" old_chat "(:|$)") {
                print $0
            }
            END { if (found == 0) print new_line } # Add if not found (edge case for initial adding)
        ' "$TELEGRAM_USERS_FILE" > "${TELEGRAM_USERS_FILE}.tmp" && \
        mv "${TELEGRAM_USERS_FILE}.tmp" "$TELEGRAM_USERS_FILE" || error_exit "Failed to update Telegram user"

    else
        echo "${escaped_username}:${chat_id}:${proxy_address}" >> "$TELEGRAM_USERS_FILE" || error_exit "Failed to save Telegram user"
    fi

    chmod 600 "$TELEGRAM_USERS_FILE" || error_exit "Failed to set permissions for Telegram users file"
    chown www-data:www-data "$TELEGRAM_USERS_FILE" || error_exit "Failed to set ownership for Telegram users file"
    log "${GREEN}Telegram user '${username}' (ID: ${chat_id}) saved/updated.${NC}"
}

# List Telegram users (updated to display proxy_address)
list_telegram_users() {
    if [[ ! -f "$TELEGRAM_USERS_FILE" ]] || [[ ! -s "$TELEGRAM_USERS_FILE" ]]; then
        echo -e "${YELLOW}No saved Telegram users found.${NC}"
        return 1
    fi

    echo -e "\n${BLUE}Saved Telegram Users:${NC}"
    local i=1
    # Read line by line, then use cut to safely parse fields, especially the last one
    while read -r line || [[ -n "$line" ]]; do
        local username=$(echo "$line" | cut -d':' -f1)
        local chat_id=$(echo "$line" | cut -d':' -f2)
        local proxy_address=$(echo "$line" | cut -d':' -f3-) # Get everything from the 3rd field onwards

        # Unescape username if it was escaped for display
        local display_username=$(echo "$username" | sed 's/\\:/!COLON!/g' | sed 's/:/ /g' | sed 's/!COLON!/:/g')
        local display_proxy=""
        if [[ -n "$proxy_address" ]]; then
            display_proxy=", Proxy: $proxy_address"
        fi
        echo -e "${GREEN}$i) Username: $display_username, Chat ID: $chat_id${display_proxy}${NC}"
        ((i++))
    done < "$TELEGRAM_USERS_FILE"
    return 0
}

# Delete Telegram user
delete_telegram_user() {
    local user_num="$1"
    if [[ ! -f "$TELEGRAM_USERS_FILE" ]] || [[ ! -s "$TELEGRAM_USERS_FILE" ]]; then
        log "${YELLOW}No Telegram users to delete.${NC}"
        return
    fi

    local num_users=$(wc -l < "$TELEGRAM_USERS_FILE")
    if (( user_num < 1 || user_num > num_users )); then
        error_exit "Invalid user number: $user_num"
    fi

    local user_line=$(sed -n "${user_num}p" "$TELEGRAM_USERS_FILE")
    local username=$(echo "$user_line" | cut -d':' -f1) # Safely get username

    sed -i "${user_num}d" "$TELEGRAM_USERS_FILE" || error_exit "Failed to delete Telegram user."
    chmod 600 "$TELEGRAM_USERS_FILE" || error_exit "Failed to set permissions for Telegram users file"
    chown www-data:www-data "$TELEGRAM_USERS_FILE" || error_exit "Failed to set ownership for Telegram users file"
    log "${GREEN}Telegram user '${username}' deleted successfully.${NC}"
}

# Manage Telegram users menu
manage_telegram_users_menu() {
    while true; do
        clear
        echo -e "${BLUE}==== Manage Telegram Users ====${NC}"
        list_telegram_users # List existing users

        echo -e "\n${GREEN}1) Add New Telegram User"
        echo -e "2) Edit Existing Telegram User"
        echo -e "3) Delete Telegram User"
        echo -e "0) Back to Main Menu${NC}"
        echo -e "==========================================="

        read -p "Choose an option: " choice
        case $choice in
            1)
                read -p "Enter recipient's Telegram Chat ID: " CHAT_ID
                read -p "Enter a username for this recipient (e.g., 'JohnDoe'): " USERNAME
                read -p "Enter Telegram proxy link (optional, e.g., 'https://t.me/proxy?server=...'): " TELEGRAM_PROXY_LINK_TO_SAVE
                add_telegram_user "$USERNAME" "$CHAT_ID" "$TELEGRAM_PROXY_LINK_TO_SAVE"
                ;;
            2)
                if list_telegram_users; then
                    read -p "Enter the number of the user to edit: " user_num
                    local num_users=$(wc -l < "$TELEGRAM_USERS_FILE")
                    if (( user_num < 1 || user_num > num_users )); then
                        echo -e "${RED}Invalid user number.${NC}"
                    else
                        local current_line=$(sed -n "${user_num}p" "$TELEGRAM_USERS_FILE")
                        # Use cut to safely parse the current line
                        local current_username=$(echo "$current_line" | cut -d':' -f1)
                        local current_chat_id=$(echo "$current_line" | cut -d':' -f2)
                        local current_proxy_address=$(echo "$current_line" | cut -d':' -f3-) # Get full proxy link

                        echo -e "${YELLOW}Editing user: $(echo "$current_username" | sed 's/\\:/!COLON!/g' | sed 's/:/ /g' | sed 's/!COLON!/:/g') (Chat ID: ${current_chat_id}, Proxy: ${current_proxy_address})${NC}"
                        read -p "Enter new username (current: ${current_username}, press Enter to keep): " new_username
                        new_username=${new_username:-$current_username}
                        read -p "Enter new Chat ID (current: ${current_chat_id}, press Enter to keep): " new_chat_id
                        new_chat_id=${new_chat_id:-$current_chat_id}
                        read -p "Enter new Telegram proxy link (current: ${current_proxy_address}, press Enter to keep, or enter 'none' to clear): " new_proxy_link
                        if [[ "$new_proxy_link" == "none" ]]; then
                            new_proxy_link=""
                        else
                            new_proxy_link=${new_proxy_link:-$current_proxy_address}
                        fi

                        # Delete old entry and add new one
                        delete_telegram_user "$user_num" # Temporarily delete to rewrite
                        add_telegram_user "$new_username" "$new_chat_id" "$new_proxy_link"
                        log "${GREEN}User '$(echo "$new_username" | sed 's/\\:/!COLON!/g' | sed 's/:/ /g' | sed 's/!COLON!/:/g')' updated successfully.${NC}"
                    fi
                fi
                ;;
            3)
                if list_telegram_users; then
                    read -p "Enter the number of the user to delete: " user_num
                    delete_telegram_user "$user_num"
                fi
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac
        read -p "Press Enter to continue..."
    done
}


# ==============================================
# INSTALLATION FUNCTIONS
# ==============================================

# Setup UFW firewall rules
setup_ufw_rules() {
  log "Configuring UFW firewall rules..."

  ufw --force reset || error_exit "Failed to reset UFW"
  ufw default deny incoming || error_exit "Failed to set UFW defaults"
  ufw default allow outgoing || error_exit "Failed to set UFW defaults"
  ufw limit ssh || error_exit "Failed to configure SSH in UFW"
  ufw allow http/tcp || error_exit "Failed to allow HTTP (port 80)"
  ufw allow https/tcp || error_exit "Failed to allow HTTPS (port 443)"

  if [[ -n "$NGINX_PORT" ]]; then
    ufw allow "$NGINX_PORT"/tcp comment "NGINX Whitelist Gateway Port" || error_exit "Failed to allow NGINX whitelist port"
  fi

  if [[ -n "$PROXY_PORT" ]]; then
    ufw allow "$PROXY_PORT"/tcp comment "MTProto Proxy Port" || error_exit "Failed to allow MTProto proxy port"
  fi

  ufw --force enable || error_exit "Failed to enable UFW"
  log "${GREEN}Firewall configured successfully${NC}"
}

# Install MTProto Proxy
install_mtproto_proxy() {
  log "Installing MTProto Proxy..."

  cd /opt || error_exit "Failed to change to /opt directory"

  # Download with retry logic
  local retries=3
  local success=false

  for ((i=1; i<=retries; i++)); do
    log "Downloading MTProto Proxy installer (attempt $i/$retries)..."
    if curl -o MTProtoProxyInstall.sh -L https://git.io/fjo34; then
      success=true
      break
    fi
    sleep 5
  done

  if [[ "$success" != true ]]; then
    error_exit "Failed to download MTProtoProxyInstall.sh after $retries attempts"
  fi

  chmod +x MTProtoProxyInstall.sh || error_exit "Failed to make installer executable"
  bash MTProtoProxyInstall.sh || error_exit "MTProto Proxy installation failed"

  log "${GREEN}MTProto Proxy installed successfully${NC}"
}

# Install MTProto Proxy (Method 2 - alternative)
install_mtproto_proxy_method2() {
  log "Installing MTProto Proxy (Method 2)..."
  cd /opt || error_exit "Failed to change to /opt directory"
  if curl -L -o mtp_install.sh https://git.io/fj5ru; then
    chmod +x mtp_install.sh || error_exit "Failed to make installer executable"
    bash mtp_install.sh || error_exit "MTProto Proxy installation failed"
  else
    error_exit "Failed to download mtp_install.sh"
  fi
  log "${GREEN}MTProto Proxy installed successfully (Method 2)${NC}"
}

# Install NGINX with stream module
install_nginx_with_stream() {
  log "Installing NGINX with stream module..."

  apt install -y ufw fail2ban nginx libnginx-mod-stream || error_exit "Failed to install packages"

  mkdir -p /etc/nginx/stream.d || error_exit "Failed to create stream.d directory"
  touch "$STREAM_CONF_FILE" || error_exit "Failed to create stream config file"

  # Add stream block if not exists
  if ! grep -q "stream {" "$NGINX_STREAM_CONF"; then
    sed -i "/http {/i \\
stream {\\
    include /etc/nginx/stream.d/*.conf;\\
}" "$NGINX_STREAM_CONF" || error_exit "Failed to modify nginx.conf"
  fi

  log "${GREEN}NGINX installed successfully${NC}"
}

# Install PHP
install_php() {
  log "Installing PHP..."

  apt install -y php php-cli php-fpm php-curl || error_exit "Failed to install PHP packages"
  get_php_version

  log "${GREEN}PHP $PHP_VERSION installed successfully${NC}"
}

# Install Certbot
install_certbot() {
  log "Installing Certbot..."

  apt install -y certbot python3-certbot-nginx || error_exit "Failed to install Certbot"

  log "${GREEN}Certbot installed successfully${NC}"
}

# Create password file
create_password() {
  log "Creating password file..."

  while true; do
    read -p "Enter new password for IP whitelist page (min 12 chars): " -s PASSWORD
    echo
    if [[ ${#PASSWORD} -ge 12 ]]; then
      break
    fi
    echo -e "${YELLOW}Password must be at least 12 characters long.${NC}"
  done

  read -p "Confirm new password: " -s PASSWORD_CONFIRM
  echo

  if [[ "$PASSWORD" != "$PASSWORD_CONFIRM" ]]; then
    error_exit "Passwords do not match!"
  fi

  SALT=$(openssl rand -hex 8) || error_exit "Failed to generate salt"
  HASHED_PASSWORD=$(echo -n "$PASSWORD$SALT" | sha256sum | awk '{print $1}') || error_exit "Failed to hash password"

  echo "$HASHED_PASSWORD:$SALT" > "$PASSWORD_FILE" || error_exit "Failed to create password file"
  chmod 600 "$PASSWORD_FILE" || error_exit "Failed to set password file permissions"
  chown www-data:www-data "$PASSWORD_FILE" || error_exit "Failed to set password file ownership"

  log "${GREEN}Password file created successfully${NC}"
}

# Create necessary files and set permissions
create_files_and_permissions() {
  log "Creating files and setting permissions..."

  mkdir -p "$WEB_DIR" || error_exit "Failed to create web directory"
  touch "$WHITE_LIST_FILE" || error_exit "Failed to create whitelist file"
  chmod 644 "$WHITE_LIST_FILE" || error_exit "Failed to set whitelist file permissions"

  touch "$USED_TOKENS_FILE" || error_exit "Failed to create used tokens file"
  chmod 600 "$USED_TOKENS_FILE" || error_exit "Failed to set tokens file permissions"

  touch "$TELEGRAM_USERS_FILE" || error_exit "Failed to create Telegram users file"
  chmod 600 "$TELEGRAM_USERS_FILE" || error_exit "Failed to set permissions for Telegram users file"
  chown www-data:www-data "$TELEGRAM_USERS_FILE" || error_exit "Failed to set ownership for Telegram users file"

  touch "$TELEGRAM_BOT_TOKEN_FILE" || error_exit "Failed to create Telegram bot token file"
  chmod 600 "$TELEGRAM_BOT_TOKEN_FILE" || error_exit "Failed to set permissions for Telegram bot token file."
  chown root:root "$TELEGRAM_BOT_TOKEN_FILE" || error_exit "Failed to set ownership for Telegram bot token file."

  if [[ ! -f "$PASSWORD_FILE" ]]; then
    create_password
  else
    # Read existing password hash and salt
    local passdata
    passdata=$(cat "$PASSWORD_FILE") || error_exit "Failed to read password file"
    HASHED_PASSWORD="${passdata%%:*}"
    SALT="${passdata##*:}"
  fi

  # Create PHP script (Logic for long links with pass/token)
  cat > "$WEB_DIR/post.php" <<'EOF'
<?php
function is_password_correct($pass, $salt, $stored_hash) {
    return hash('sha256', $pass . $salt) === $stored_hash;
}

function token_used($token, $used_tokens_file) {
    $used_tokens = file_exists($used_tokens_file) ? file($used_tokens_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    return in_array($token, $used_tokens);
}

function mark_token_used($token, $used_tokens_file) {
    file_put_contents($used_tokens_file, $token . "\n", FILE_APPEND | LOCK_EX);
}

function is_one_time_token_valid($token, $secret, $used_tokens_file) {
    if (token_used($token, $used_tokens_file)) return false;
    $decoded = base64_decode($token, true);
    if (!$decoded) return false;
    $parts = explode(':', $decoded);
    if (count($parts) !== 2) return false;
    list($timestamp, $hash) = $parts;
    if (!ctype_digit($timestamp)) return false;
    if (time() - intval($timestamp) > 2592000) return false; // 30 days expiry
    $check_hash = hash('sha256', $secret . $timestamp);
    if (!hash_equals($check_hash, $hash)) return false;
    return true;
}

function is_five_min_token_valid($token, $secret) {
    $decoded = base64_decode($token, true);
    if (!$decoded) return false;
    $parts = explode(':', $decoded);
    if (count($parts) !== 2) return false;
    list($timestamp, $hash) = $parts;
    if (!ctype_digit($timestamp)) return false;
    if (time() - intval($timestamp) > 900) return false; // 15 min expiry
    $check_hash = hash('sha256', $secret . $timestamp);
    if (!hash_equals($check_hash, $hash)) return false;
    return true;
}

// Main
$password_file = "/etc/nginx/.password";
$used_tokens_file = "/etc/nginx/used_tokens.txt";
$whitelist_file = "/etc/nginx/whitelist.txt";

// Determine client IP, prioritizing X-Real-IP or X-Forwarded-For if set by a trusted proxy
$ip = $_SERVER['REMOTE_ADDR'];
if (isset($_SERVER['HTTP_X_REAL_IP']) && $_SERVER['HTTP_X_REAL_IP'] !== '') {
    $ip = $_SERVER['HTTP_X_REAL_IP'];
} elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && $_SERVER['HTTP_X_FORWARDED_FOR'] !== '') {
    // Take the first IP if there are multiple (e.g., from multiple proxies)
    $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
}

list($stored_hash, $salt) = explode(":", trim(file_get_contents($password_file)));

if (!isset($_GET['pass']) || empty($_GET['pass'])) {
    http_response_code(400);
    exit("Missing required parameter: pass");
}
$pass = base64_decode(strtr($_GET['pass'], '_-', '/+'));

$token = isset($_GET['token']) ? $_GET['token'] : '';
if (empty($token)) {
    http_response_code(400);
    exit("Missing required parameter: token");
}

if (!is_password_correct($pass, $salt, $stored_hash)) {
    http_response_code(403);
    exit("Access denied: Incorrect password.");
}

$secret = hash('sha256', $pass . $salt);

if (is_one_time_token_valid($token, $secret, $used_tokens_file)) {
    mark_token_used($token, $used_tokens_file);
} elseif (is_five_min_token_valid($token, $secret)) {
    // Valid token, continue
} else {
    http_response_code(403);
    exit("Access denied: Invalid or expired token.");
}

// Prepare the new entry with a timestamp
$timestamp = date('Y-m-d H:i:s');
$new_entry_base = "allow $ip;";
$new_entry_with_timestamp = "$new_entry_base # added $timestamp\n";

$existing_lines = file_exists($whitelist_file) ? file($whitelist_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

$ip_already_whitelisted = false;
foreach ($existing_lines as $line) {
    # Check if the IP is already in the whitelist, ignoring the timestamp comment
    if (strpos(trim($line), $new_entry_base) === 0) {
        $ip_already_whitelisted = true;
        break;
    }
}

if (!$ip_already_whitelisted) {
    file_put_contents($whitelist_file, $new_entry_with_timestamp, FILE_APPEND | LOCK_EX);
    echo "IP $ip added to whitelist.";
} else {
    echo "IP $ip is already whitelisted.";
}
?>
EOF

  chmod 644 "$WEB_DIR"/*.php || error_exit "Failed to set PHP file permissions"

  log "${GREEN}Files created and permissions set successfully${NC}"
}

# Setup NGINX site configuration (Includes robust PHP processing)
# Setup NGINX site configuration (Includes robust PHP processing)
# ... (previous code) ...

# Setup NGINX site configuration (Includes robust PHP processing)
setup_nginx_site() {
  log "Configuring NGINX site..."

  while true; do
    read -p "Enter your domain (must already point to this server): " DOMAIN
    validate_domain "$DOMAIN" && break
  done

  # Pre-flight check: Domain resolution
  check_domain_resolution "$DOMAIN"

  while true; do
    read -p "Enter your Telegram proxy port (e.g., 48500): " -i "48500" -e PROXY_PORT # Added default
    validate_port "$PROXY_PORT" && break
  done

  while true; do
    read -p "Enter NGINX whitelist gateway port (e.g., 8443): " -i "8443" -e NGINX_PORT # Added default
    validate_port "$NGINX_PORT" && break
  done

  get_php_version
  if [[ -z "$PHP_VERSION" ]]; then
    error_exit "PHP version could not be detected"
  fi
  # Prompt for proxy protocol configuration
  local use_proxy_protocol="n"
  read -p "Are you using a load balancer/proxy that sends PROXY protocol (e.g., Cloudflare, HAProxy)? [y/N]: " use_proxy_protocol
  use_proxy_protocol=$(echo "$use_proxy_protocol" | tr '[:upper:]' '[:lower:]')

  local proxy_ip_range=""
  if [[ "$use_proxy_protocol" == "y" ]]; then
      read -p "Enter the IP address or CIDR range of your trusted proxy (e.g., 192.168.1.0/24 or 0.0.0.0/0 for all, but use with caution!): " proxy_ip_range
      if [[ -z "$proxy_ip_range" ]]; then
          error_exit "Proxy IP range cannot be empty if PROXY protocol is enabled."
      fi
  fi

  # Create an initial HTTP server block (Certbot needs something to modify)
  # This block will be overwritten later, but Certbot expects a server block for the domain.
  cat > "$WHITELIST_SITE_CONF" <<EOF
server {
  listen 80;
  server_name $DOMAIN;
  root $WEB_DIR;
  index index.php index.html;
  location / {
    try_files \$uri \$uri/ =404;
  }
}
EOF

  # Create symlink (should be done before Certbot runs)
  ln -sf "$WHITELIST_SITE_CONF" "$NGINX_SITES_LINK" || error_exit "Failed to create NGINX symlink"

  # Obtain SSL certificate
  log "Obtaining SSL certificate..."
  local cert_success=false
  local ssl_cert_path="/etc/ssl/certs/nginx-selfsigned.crt" # Default to self-signed paths
  local ssl_key_path="/etc/ssl/private/nginx-selfsigned.key"
  local ssl_trusted_cert_path="" # Default to empty for self-signed

  if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m admin@$DOMAIN; then
    log "${GREEN}Certbot SSL certificate obtained successfully.${NC}"
    cert_success=true
    ssl_cert_path="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    ssl_key_path="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    ssl_trusted_cert_path="/etc/letsencrypt/live/$DOMAIN/chain.pem"
  else
    log "${YELLOW}Certbot failed to obtain certificate. Falling back to self-signed certificate.${NC}"
    # Ensure self-signed certificate is generated only if Certbot failed
    if openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$ssl_key_path" \
      -out "$ssl_cert_path" \
      -subj "/CN=$DOMAIN"; then
      log "${GREEN}Self-signed certificate created successfully.${NC}"
    else
      error_exit "Failed to create self-signed certificate after Certbot failure."
    fi
    cert_success=false
  fi


  # Create the final NGINX server block (HTTPS and HTTP redirect)
  cat > "$WHITELIST_SITE_CONF" <<EOF
server {
    listen 443 ssl http2 $(if [[ "$use_proxy_protocol" == "y" ]]; then echo "proxy_protocol"; fi);
    listen [::]:443 ssl http2 $(if [[ "$use_proxy_protocol" == "y" ]]; then echo "proxy_protocol"; fi);
    server_name $DOMAIN;

    root $WEB_DIR;
    index index.php index.html index.htm;

    $(if [[ "$use_proxy_protocol" == "y" ]]; then
      echo "  set_real_ip_from $proxy_ip_range;"
      echo "  real_ip_header proxy_protocol;"
    fi)

    ssl_certificate $ssl_cert_path;
    ssl_certificate_key $ssl_key_path;
    $(if [[ -n "$ssl_trusted_cert_path" ]]; then echo "    ssl_trusted_certificate $ssl_trusted_cert_path;"; fi) # Only include if chain exists

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
#    ssl_stapling on;
#    ssl_stapling_verify on;
#    resolver 8.8.8.8 8.8.4.4 valid=300s;
#    resolver_timeout 5s;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    server_tokens off;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ /\.ht {
        deny all;
    }

    location ~ \.php\$ {
        # Ensure the PHP file exists before passing to FPM
        try_files \$uri =404;

        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:/run/php/php$PHP_VERSION-fpm.sock; # Uses detected PHP version
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params; # Ensure this is included after SCRIPT_FILENAME

        # Pass real IP to PHP (NGINX updates \$remote_addr after proxy_protocol processing)
        $(if [[ "$use_proxy_protocol" == "y" ]]; then
          echo "    fastcgi_param REMOTE_ADDR \$remote_addr;"
          echo "    fastcgi_param HTTP_X_REAL_IP \$remote_addr;"
          echo "    fastcgi_param HTTP_X_FORWARDED_FOR \$remote_addr;"
        fi)
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
EOF

  # Create stream configuration
  mkdir -p "$(dirname "$STREAM_CONF_FILE")" || error_exit "Failed to create stream.d directory"
  cat > "$STREAM_CONF_FILE" <<EOF
server {
    listen $NGINX_PORT;
    proxy_pass 127.0.0.1:$PROXY_PORT;
    proxy_timeout 20m;
    proxy_connect_timeout 1s;

    allow 127.0.0.1;
    include $WHITE_LIST_FILE;
    deny all;
}
EOF

  # Set secure permissions
  chmod 755 /etc/nginx || error_exit "Failed to set NGINX directory permissions" # Changed to 755 for broader access
  systemctl reload nginx || error_exit "Failed to reload NGINX"

  save_config

  log "${GREEN}NGINX site configured successfully${NC}"
}
# ... (rest of the script) ...

# Fix permissions (also includes verification)
fix_permissions() {
  log "Fixing and Verifying permissions..."

  chown -R www-data:www-data "$WEB_DIR" || error_exit "Failed to set web directory ownership"
  chown www-data:www-data "$PASSWORD_FILE" || error_exit "Failed to set password file ownership"
  chown www-data:www-data "$WHITE_LIST_FILE" || error_exit "Failed to set whitelist file ownership"
  chown www-data:www-data "$USED_TOKENS_FILE" || error_exit "Failed to set tokens file ownership"
  chown www-data:www-data "$TELEGRAM_USERS_FILE" || error_exit "Failed to set ownership for Telegram users file"
  chown root:root "$TELEGRAM_BOT_TOKEN_FILE" || error_exit "Failed to set ownership for Telegram bot token file"

  chmod 644 "$WEB_DIR"/*.php || error_exit "Failed to set PHP file permissions"
  chmod 600 "$PASSWORD_FILE" || error_exit "Failed to set password file permissions"
  chmod 600 "$WHITE_LIST_FILE" || error_exit "Failed to set whitelist file permissions"
  chmod 600 "$USED_TOKENS_FILE" || error_exit "Failed to set tokens file permissions"
  chmod 600 "$TELEGRAM_USERS_FILE" || error_exit "Failed to set permissions for Telegram users file"
  chmod 600 "$TELEGRAM_BOT_TOKEN_FILE" || error_exit "Failed to set permissions for Telegram bot token file."

  chmod 755 /etc/nginx || error_exit "Failed to set NGINX directory permissions"
  chmod 755 /var/www || error_exit "Failed to set www directory permissions"
  chmod 755 "$WEB_DIR" || error_exit "Failed to set web directory permissions"

  # Verify permissions
  local success=true
  sudo -u www-data test -r "$PASSWORD_FILE" || { log "${YELLOW}Warning: www-data cannot read password file${NC}"; success=false; }
  sudo -u www-data test -w "$WHITE_LIST_FILE" || { log "${YELLOW}Warning: www-data cannot write to whitelist${NC}"; success=false; }
  sudo -u www-data test -w "$USED_TOKENS_FILE" || { log "${YELLOW}Warning: www-data cannot write to used tokens file${NC}"; success=false; }
  sudo -u www-data test -r "$TELEGRAM_USERS_FILE" || { log "${YELLOW}Warning: www-data cannot read Telegram users file${NC}"; success=false; }
  sudo -u www-data test -w "$TELEGRAM_USERS_FILE" || { log "${YELLOW}Warning: www-data cannot write to Telegram users file${NC}"; success=false; }
  sudo -u root test -r "$TELEGRAM_BOT_TOKEN_FILE" || { log "${YELLOW}Warning: root cannot read Telegram bot token file${NC}"; success=false; }

  # Set stream config permissions
  chown root:root "$STREAM_CONF_FILE" || error_exit "Failed to set stream config ownership"
  chmod 644 "$STREAM_CONF_FILE" || error_exit "Failed to set stream config permissions"

  if [[ "$success" = true ]]; then
    log "${GREEN}Permissions fixed and verified successfully${NC}"
  else
    log "${YELLOW}Some permissions issues might persist. Please review warnings above.${NC}"
  fi
}

# Configure Fail2ban jails for NGINX and PHP-FPM
configure_fail2ban() {
    log "Configuring Fail2ban jails for NGINX and PHP-FPM..."

    # NGINX HTTP/HTTPS jail
    cat > "/etc/fail2ban/jail.d/nginx-whitelist.conf" <<EOF
[nginx-whitelist]
enabled = true
port = http,https,$NGINX_PORT
filter = nginx-whitelist
logpath = /var/log/nginx/access.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

    # NGINX filter for whitelist attempts (adjust to only match pass/token, no id)
    cat > "/etc/fail2ban/filter.d/nginx-whitelist.conf" <<EOF
[Definition]
failregex = <HOST> -.*"GET /post.php.*(pass=|token=).*HTTP.*" (400|403)
ignoreregex =
EOF

    # PHP-FPM jail (if PHP-FPM logs to a separate file, otherwise NGINX access.log is primary)
    log "Fail2ban configuration primarily targets NGINX access.log for whitelist attempts."
    log "If PHP-FPM errors are logged separately with IP, consider adding a specific PHP-FPM jail."

    # Enable Fail2ban to start on boot
    systemctl enable fail2ban || error_exit "Failed to enable Fail2ban"
    # Restart Fail2ban to apply new configuration
    systemctl restart fail2ban || error_exit "Failed to restart Fail2ban"
    log "${GREEN}Fail2ban configured, enabled, and restarted.${NC}"
}

# Clean old whitelist entries
clean_old_whitelist_entries() {
    log "Cleaning old whitelist entries..."
    local temp_whitelist_file=$(mktemp)
    local current_timestamp=$(date +%s)
    local expiry_seconds=2592000 # 30 days, matches one-time token expiry

    if [[ ! -f "$WHITE_LIST_FILE" ]] || [[ ! -s "$WHITE_LIST_FILE" ]]; then
        log "${YELLOW}Whitelist file not found or is empty, nothing to clean.${NC}"
        return
    fi

    while IFS= read -r line; do
        # Extract timestamp from comment
        local timestamp_str=$(echo "$line" | sed -n 's/.*# added \([0-9\-]\{10\} [0-9:]\{8\}\)/\1/p')

        if [[ -n "$timestamp_str" ]]; then
            # Convert timestamp string to seconds since epoch
            local entry_timestamp=$(date -d "$timestamp_str" +%s 2>/dev/null)

            if [[ -n "$entry_timestamp" && "$((current_timestamp - entry_timestamp))" -lt "$expiry_seconds" ]]; then
                echo "$line" >> "$temp_whitelist_file"
            else
                log "Removed expired entry: $line"
            fi
        else
            # Keep lines without a timestamp (e.g., manually added, or from older versions)
            echo "$line" >> "$temp_whitelist_file"
        fi
    done < "$WHITE_LIST_FILE"

    mv "$temp_whitelist_file" "$WHITE_LIST_FILE" || error_exit "Failed to move temporary whitelist file"
    chmod 600 "$WHITE_LIST_FILE" || error_exit "Failed to set whitelist file permissions after cleanup"
    chown www-data:www-data "$WHITE_LIST_FILE" || error_exit "Failed to set whitelist file ownership after cleanup"

    systemctl reload nginx || log "${YELLOW}Failed to reload NGINX after whitelist cleanup. Manual reload might be needed.${NC}"
    log "${GREEN}Old whitelist entries cleaned. Remember to set up a cron job for daily cleanup.${NC}"
    echo -e "\n${BLUE}To automate daily cleanup, add the following to your crontab (run 'sudo crontab -e'):${NC}"
    echo -e "${YELLOW}0 3 * * * /bin/bash $(readlink -f "$0") --clean-whitelist >> $LOG_FILE 2>&1${NC}"
    echo -e "${YELLOW}(This will run the cleanup at 3:00 AM daily. Adjust time as needed.)${NC}"
}


# Generate token URL (Generates long links with pass/token)
generate_token_url() {
  log "Generating access token URLs..."

  if [[ ! -f "$PASSWORD_FILE" ]]; then
    error_exit "Password file not found! Please install first."
  fi

  read -p "Enter your password for whitelist page: " -s PASS_INPUT
  echo

  if [[ -z "$DOMAIN" ]]; then
    read -p "Enter your domain (used in URL): " DOMAIN
    validate_domain "$DOMAIN"
  fi

  # Read salt and hashed password from file
  local raw
  raw=$(cat "$PASSWORD_FILE") || error_exit "Failed to read password file"
  local HASHED_PASSWORD="${raw%%:*}"
  local SALT="${raw##*:}"

  # Verify password
  SECRET=$(echo -n "$PASS_INPUT$SALT" | sha256sum | awk '{print $1}') || error_exit "Failed to generate secret"
  if [[ "$SECRET" != "$HASHED_PASSWORD" ]]; then
    error_exit "Password incorrect!"
  fi

  # Generate 15-minute token URL
  TIMESTAMP_5MIN=$(date +%s)
  TOKEN_HASH_5MIN=$(echo -n "${SECRET}${TIMESTAMP_5MIN}" | sha256sum | awk '{print $1}') || error_exit "Failed to generate token hash"
  TOKEN_RAW_5MIN="${TIMESTAMP_5MIN}:${TOKEN_HASH_5MIN}"
  # Ensure no newlines or padding in base64 output
  TOKEN_5MIN=$(echo -n "$TOKEN_RAW_5MIN" | base64 | tr -d '=' | tr -d '\n' | tr '/+' '_-') || error_exit "Failed to encode token"


  # Generate one-time token URL
  TIMESTAMP_OT=$(date +%s)
  TOKEN_HASH_OT=$(echo -n "${SECRET}${TIMESTAMP_OT}" | sha256sum | awk '{print $1}') || error_exit "Failed to generate token hash"
  TOKEN_RAW_OT="${TIMESTAMP_OT}:${TOKEN_HASH_OT}"
  # Ensure no newlines or padding in base64 output
  TOKEN_OT=$(echo -n "$TOKEN_RAW_OT" | base64 | tr -d '=' | tr -d '\n' | tr '/+' '_-') || error_exit "Failed to encode token"

  # Generate URLs
  PASS_B64=$(echo -n "$PASS_INPUT" | base64 | tr -d '=' | tr '/+' '_-') || error_exit "Failed to encode password"

  echo -e "\n${GREEN}Your access URLs:${NC}"
  echo -e "1) ${BLUE}One-time token URL${NC} (valid for single use within 30 days):"
  echo "https://$DOMAIN/post.php?pass=$PASS_B64&token=$TOKEN_OT"

  echo -e "\n2) ${BLUE}15-minute token URL${NC} (valid for 15 minutes, reusable):"
  echo "https://$DOMAIN/post.php?pass=$PASS_B64&token=$TOKEN_5MIN"

  echo -e "\n${YELLOW}NOTE:${NC} Use one-time token once only, 15-minute token can be used multiple times within 15 mins."
}

send_whitelist_link_telegram() {
    local CURRENT_BOT_TOKEN="$TELEGRAM_BOT_TOKEN" # Use the globally loaded token
    local CHAT_ID=""
    local USERNAME=""
    local TELEGRAM_PROXY_LINK_TO_SEND="" # Renamed for clarity - this is the link to send to the user
    local choice=""
    local use_saved_token="n"

    # Check if DOMAIN and PASSWORD_FILE are set
    if [[ -z "$DOMAIN" ]]; then
        log "${YELLOW}Domain not set. Please run option 2 to install the whitelist system first.${NC}"
        return
    fi
    if [[ ! -f "$PASSWORD_FILE" ]]; then
        log "${YELLOW}Password file not found. Please run option 2 to install the whitelist system first.${NC}"
        return
    fi

    # Read salt and hashed password from file to set SECRET and PASS_B64
    local raw
    raw=$(cat "$PASSWORD_FILE") || error_exit "Failed to read password file"
    local HASHED_PASSWORD_STORED="${raw%%:*}"
    local SALT_STORED="${raw##*:}"

    read -p "Enter your password for whitelist page to generate token: " -s PASS_INPUT
    echo

    SECRET=$(echo -n "$PASS_INPUT$SALT_STORED" | sha256sum | awk '{print $1}') || error_exit "Failed to generate secret"
    if [[ "$SECRET" != "$HASHED_PASSWORD_STORED" ]]; then
        error_exit "Password incorrect! Cannot generate token."
    fi
    # PASS_B64 is needed to derive SECRET in PHP for the long link format
    PASS_B64=$(echo -n "$PASS_INPUT" | base64 | tr -d '=' | tr '/+' '_-') || error_exit "Failed to encode password"


    # Handle Telegram Bot Token
    if [[ -n "$CURRENT_BOT_TOKEN" ]]; then
        read -p "Existing Telegram Bot Token found. Use it? [Y/n]: " use_saved_token
        use_saved_token=$(echo "$use_saved_token" | tr '[:upper:]' '[:lower:]')
        if [[ "$use_saved_token" == "n" ]]; then
            read -p "Enter new Telegram Bot Token: " BOT_TOKEN_INPUT
            save_telegram_bot_token "$BOT_TOKEN_INPUT"
            CURRENT_BOT_TOKEN="$BOT_TOKEN_INPUT"
        else
            log "Using saved Telegram Bot Token."
        fi
    else
        read -p "No Telegram Bot Token found. Please enter it now: " BOT_TOKEN_INPUT
        save_telegram_bot_token "$BOT_TOKEN_INPUT"
        CURRENT_BOT_TOKEN="$BOT_TOKEN_INPUT"
    fi


 # --- Start of user-friendly improvements ---
    if list_telegram_users; then # This function returns 0 if users exist, 1 otherwise
        echo -e "\n${BLUE}How would you like to send the whitelist link?${NC}"
        while true; do
            read -p "  (E) Send to an existing saved user, or (N) Enter details for a new user? [E/N]: " choice
            choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
            if [[ "$choice" == "e" || "$choice" == "n" ]]; then
                break
            else
                echo -e "${RED}Invalid choice. Please type 'E' for existing or 'N' for new.${NC}"
            fi
        done
    else
        # No saved users, force new user entry
        choice="n"
        echo -e "${YELLOW}No saved Telegram users found. You will be prompted to enter details for a new user.${NC}"
    fi

    if [[ "$choice" == "e" ]]; then
        echo -e "\n${BLUE}Please enter the number of the user from the list above to send the link to.${NC}"
        read -p "Enter user number (or 0 to go back): " user_num
        if [[ "$user_num" -eq 0 ]]; then
            log "${YELLOW}User selection cancelled.${NC}"
            return # Exit the function if user cancels
        fi

        local num_users=$(wc -l < "$TELEGRAM_USERS_FILE")
        if (( user_num < 1 || user_num > num_users )); then
            error_exit "${RED}Invalid user number: ${user_num}. Please choose a number from the list.${NC}"
        fi

        local user_line=$(sed -n "${user_num}p" "$TELEGRAM_USERS_FILE")
        # Safely parse the line using cut
        USERNAME=$(echo "$user_line" | cut -d':' -f1)
        CHAT_ID=$(echo "$user_line" | cut -d':' -f2)
        TELEGRAM_PROXY_LINK_TO_SEND=$(echo "$user_line" | cut -d':' -f3-) # Get everything from 3rd field onwards

        log "Selected existing user: $(echo "$USERNAME" | sed 's/\\:/!COLON!/g' | sed 's/:/ /g' | sed 's/!COLON!/:/g') (ID: $CHAT_ID)"
        if [[ -n "$TELEGRAM_PROXY_LINK_TO_SEND" ]]; then
            log "Stored Telegram Proxy Link for user: ${TELEGRAM_PROXY_LINK_TO_SEND}"
        fi
    else # choice == "n"
        echo -e "\n${BLUE}Please enter the details for the new Telegram user.${NC}"
        read -p "Enter recipient's Telegram Chat ID: " CHAT_ID
        read -p "Enter a username for this recipient (e.g., 'JohnDoe'): " USERNAME
        read -p "Enter Telegram proxy link (optional, e.g., 'https://t.me/proxy?server=...'): " TELEGRAM_PROXY_LINK_TO_SEND
    fi
    # --- End of user-friendly improvements ---

    # Generate a fresh one-time token for sending via Telegram
    local TIMESTAMP_OT_TELEGRAM=$(date +%s)
    local TOKEN_HASH_OT_TELEGRAM=$(echo -n "${SECRET}${TIMESTAMP_OT_TELEGRAM}" | sha256sum | awk '{print $1}') || error_exit "Failed to generate token hash for Telegram"
    local TOKEN_RAW_OT_TELEGRAM="${TIMESTAMP_OT_TELEGRAM}:${TOKEN_HASH_OT_TELEGRAM}"
    # Ensure no newlines or padding in base64 output
    local TOKEN_OT_TELEGRAM=$(echo -n "$TOKEN_RAW_OT_TELEGRAM" | base64 | tr -d '=' | tr -d '\n' | tr '/+' '_-') || error_exit "Failed to encode token for Telegram"

    WHITELIST_LINK="https://${DOMAIN}/post.php?pass=${PASS_B64}&token=${TOKEN_OT_TELEGRAM}"

    # Construct the message including the whitelist link and optionally the proxy link
    local LINK_TEXT="                1: Click here to whitelist your IP"
    local MESSAGE="*Hello                           ${USERNAME}
Your whitelist link* (valid for a limited time, one-time use): 
    [${LINK_TEXT}](${WHITELIST_LINK})
*This link is for one-time use and expires in 30 days.*
* Please click it from the device whose IP you wish to whitelist.*"

    # IMPORTANT: Do NOT include Bash color codes (${BLUE}, ${NC}) in the message sent to Telegram.
    # They will break Markdown parsing.
    if [[ -n "$TELEGRAM_PROXY_LINK_TO_SEND" ]]; then
        MESSAGE+="
*To configure your Telegram client with a proxy, click here:*
                             2: [Proxy Link](${TELEGRAM_PROXY_LINK_TO_SEND})"
        log "Adding Telegram proxy link to message: ${TELEGRAM_PROXY_LINK_TO_SEND}"
    fi

    log "Attempting to send message to Telegram user ${CHAT_ID}..."
    response=$(curl -s -X POST "https://api.telegram.org/bot${CURRENT_BOT_TOKEN}/sendMessage" \
        -d chat_id="${CHAT_ID}" \
        --data-urlencode text="${MESSAGE}" \
        -d parse_mode="Markdown")

    echo "Telegram API response: $response"
    if echo "$response" | grep -q '"ok":true'; then
        log "${GREEN}Whitelist link sent to Telegram user $(echo "$USERNAME" | sed 's/\\:/!COLON!/g' | sed 's/:/ /g' | sed 's/!COLON!/:/g').${NC}"
        if [[ "$choice" == "n" ]]; then
            read -p "Do you want to save this user for future use? [y/N]: " save_user_choice
            save_user_choice=$(echo "$save_user_choice" | tr '[:upper:]' '[:lower:]')
            if [[ "$save_user_choice" == "y" ]]; then
                add_telegram_user "$USERNAME" "$CHAT_ID" "$TELEGRAM_PROXY_LINK_TO_SEND" # Save the link to file
            fi
        fi
    else
        log "${RED}Failed to send Telegram message.${NC}"
        log "Response: $response"
    fi
}

# Show system status
show_status() {
  echo -e "\n${BLUE}=== System Status ===${NC}"

  # Check NGINX
  if systemctl is-active nginx >/dev/null; then
    echo -e "NGINX: ${GREEN}RUNNING${NC}"
  else
    echo -e "NGINX: ${RED}STOPPED${NC}"
  fi

  # Check PHP-FPM
  if systemctl is-active "php$PHP_VERSION-fpm" >/dev/null; then
    echo -e "PHP-FPM: ${GREEN}RUNNING${NC}"
  else
    echo -e "PHP-FPM: ${RED}STOPPED${NC}"
  fi

  # Check whitelist count
  if [[ -f "$WHITE_LIST_FILE" ]]; then
    echo -e "Whitelisted IPs: ${CYAN}$(grep -c '^allow' "$WHITE_LIST_FILE")${NC}" # Count lines starting with 'allow'
  else
    echo -e "Whitelist file: ${RED}MISSING${NC}"
  fi

  # Check domain
  if [[ -n "$DOMAIN" ]]; then
    echo -e "Configured domain: ${CYAN}$DOMAIN${NC}"
  else
    echo -e "Domain: ${YELLOW}NOT CONFIGURED${NC}"
  fi

  # Check ports
  if [[ -n "$PROXY_PORT" ]]; then
    echo -e "Proxy port: ${CYAN}$PROXY_PORT${NC}"
  else
    echo -e "Proxy port: ${YELLOW}NOT CONFIGURED${NC}"
  fi

  if [[ -n "$NGINX_PORT" ]]; then
    echo -e "Whitelist port: ${CYAN}$NGINX_PORT${NC}"
  else
    echo -e "Whitelist port: ${YELLOW}NOT CONFIGURED${NC}"
  fi

  # Check Certbot renewal timer
  if command -v systemctl >/dev/null && systemctl list-timers | grep -q 'certbot.timer'; then
      echo -e "Certbot Auto-Renewal: ${GREEN}ENABLED${NC}"
      local next_renewal=$(systemctl list-timers certbot.timer | grep 'certbot.timer' | awk '{print $5, $6, $7}')
      echo -e "  Next renewal: ${CYAN}$next_renewal${NC}"
  else
      echo -e "Certbot Auto-Renewal: ${YELLOW}NOT FOUND/DISABLED${NC} (Manual renewal may be required)"
  fi

  # Check Fail2ban status
  if systemctl is-active fail2ban >/dev/null; then
      echo -e "Fail2ban: ${GREEN}RUNNING${NC}"
      local jails_active=$(fail2ban-client status | grep "Jail list" | sed -E 's/.*Jail list:[ \t]*(.*)/\1/; s/, / /g')
      if [[ -n "$jails_active" ]]; then
          echo -e "  Active Jails: ${CYAN}$jails_active${NC}"
      else
          echo -e "  Active Jails: ${YELLOW}None (Check configuration)${NC}"
           
      fi
  else
      echo -e "Fail2ban: ${RED}STOPPED${NC}"
  fi

  # Check saved Telegram users
  if [[ -f "$TELEGRAM_USERS_FILE" ]] && [[ -s "$TELEGRAM_USERS_FILE" ]]; then
      echo -e "Saved Telegram Users: ${CYAN}$(wc -l < "$TELEGRAM_USERS_FILE")${NC}"
  else
      echo -e "Saved Telegram Users: ${YELLOW}None${NC}"
  fi

  # Check Telegram Bot Token status
  if [[ -f "$TELEGRAM_BOT_TOKEN_FILE" ]] && [[ -s "$TELEGRAM_BOT_TOKEN_FILE" ]]; then
      echo -e "Telegram Bot Token: ${GREEN}CONFIGURED${NC}"
  else
      echo -e "Telegram Bot Token: ${YELLOW}NOT CONFIGURED${NC}"
  fi
}

# Uninstall everything
uninstall() {
  echo -e "\n${RED}=== UNINSTALL ===${NC}"
  read -p "Are you sure you want to uninstall everything? [y/N] " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Uninstall cancelled."
    return
  fi

  log "Starting uninstallation..."

  # Stop services
  systemctl stop nginx || log "${YELLOW}Failed to stop NGINX${NC}"
  systemctl stop "php$PHP_VERSION-fpm" || log "${YELLOW}Failed to stop PHP-FPM${NC}"
  systemctl stop fail2ban || log "${YELLOW}Failed to stop Fail2ban${NC}"

  # Remove Fail2ban jails
  rm -f "/etc/fail2ban/jail.d/nginx-whitelist.conf" || log "${YELLOW}Failed to remove Fail2ban jail config${NC}"
  rm -f "/etc/fail2ban/filter.d/nginx-whitelist.conf" || log "${YELLOW}Failed to remove Fail2ban filter config${NC}"
  systemctl restart fail2ban || log "${YELLOW}Failed to restart Fail2ban after removing jails${NC}"

  # Remove packages
  apt remove -y --purge nginx php-fpm php libnginx-mod-stream certbot python3-certbot-nginx fail2ban || log "${YELLOW}Failed to remove some packages${NC}"

  # Remove configuration files
  rm -rf "$WEB_DIR/post.php" || log "${YELLOW}Failed to remove PHP script${NC}"
  rm -f "$WHITE_LIST_FILE" "$USED_TOKENS_FILE" "$PASSWORD_FILE" "$TELEGRAM_USERS_FILE" "$TELEGRAM_BOT_TOKEN_FILE" || log "${YELLOW}Failed to remove data files${NC}"
  rm -f "$WHITELIST_SITE_CONF" "$NGINX_SITES_LINK" || log "${YELLOW}Failed to remove NGINX config${NC}"
  rm -f "$STREAM_CONF_FILE" || log "${YELLOW}Failed to remove stream config${NC}"
  rm -f "$CONFIG_FILE" || log "${YELLOW}Failed to remove config file${NC}"

  # Clean up
  apt autoremove -y || log "${YELLOW}Failed to autoremove packages${NC}"

  log "${GREEN}Uninstallation complete.${NC}"
}

# Install everything (excluding MTProto Proxy installation)
install_all() {
  check_root
  load_config # Load existing config to see if it's a fresh install
  create_backup

  log "Starting complete installation of whitelist system..."

  # The MTProto Proxy installation is handled separately via menu option 1
  # install_mtproto_proxy # This line remains commented out as per your request
  install_nginx_with_stream
  install_php
  install_certbot
  create_files_and_permissions
  setup_nginx_site
  configure_fail2ban # New: Configure Fail2ban
  fix_permissions # This now also handles verification
  setup_ufw_rules

  log "${GREEN}Whitelist system installation completed successfully!${NC}"
  show_status
}
# Add this function to your main script
function tor_menu() {
    GREEN="\033[0;32m"
    RED="\033[0;31m"
    YELLOW="\033[1;33m"
    BLUE="\033[1;34m"
    NC="\033[0m" # No Color

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

#Random HTML
random_template_site() {
    # Check for dependencies (wget, unzip, shuf are already checked at script start)

    # Download and extract randomfakehtml if not present
    cd "$HOME" || error_exit "Failed to change to HOME directory"

    if [[ ! -d "randomfakehtml-master" ]]; then
        log "Downloading randomfakehtml template..."
        wget -q https://github.com/GFW4Fun/randomfakehtml/archive/refs/heads/master.zip || error_exit "Failed to download randomfakehtml"
        unzip -q master.zip && rm -f master.zip || error_exit "Failed to unzip randomfakehtml"
    fi

    cd randomfakehtml-master || error_exit "Failed to change to randomfakehtml-master directory"
    rm -rf assets ".gitattributes" "README.md" "_config.yml" || true # Use || true to prevent exit if files don't exist

    # Pick a random template directory
    RandomHTML=$(find . -maxdepth 1 -type d ! -name '.' | sed 's|^\./||' | shuf -n1)
    log "Random template name selected: ${RandomHTML}"

    # Copy to web directory, but don't delete post.php
    if [[ -d "${RandomHTML}" && -d "/var/www/html/" ]]; then
        log "Copying template to web directory..."
        # Remove everything except post.php (files and directories)
        find /var/www/html/ ! -name 'post.php' -type f -exec rm -f {} +
        # Corrected path for deleting directories
        find /var/www/html/ ! -name 'post.php' -type d -mindepth 1 -exec rm -rf {} +

        cp -a "${RandomHTML}/." /var/www/html/ || error_exit "Failed to copy template files"
        log "${GREEN}Template extracted successfully!${NC}"
         # --- ADD THIS PART ---
        echo -e "\n${CYAN}To automate daily random template updates every 6 hours, add the following to your crontab:${NC}"
        echo -e "${YELLOW}sudo crontab -e${NC}"
        echo -e "${YELLOW}Then add this line to the file that opens:${NC}"
        echo -e "${YELLOW}0 */6 * * * /bin/bash $(readlink -f "$0") --random-template >> /var/log/mtproxy-whitelist.log 2>&1${NC}"
        echo -e "${YELLOW}(make sure the above line contain the place u put start.sh in crontab to get new site evry 6h)${NC}"

        echo -e "${YELLOW}(This will update the template at 00:00, 06:00, 12:00, and 18:00 daily.)${NC}"
        # --- END ADDITION ---
    else
        error_exit "Extraction error: Template directory not found or web directory missing."
    fi
}
if [[ "$#" -eq 1 && "$1" == "--random-template" ]]; then
    log "Script called for automated random template update."
    random_template_site
    exit 0
fi


# ==============================================
# MAIN MENU
# ==============================================

show_menu() {
  while true; do
    clear
    echo -e "${BLUE}==== MTProto Proxy Whitelist Installer ====${NC}"
    echo -e "${GREEN}1) Install MTProto Proxy only (choose installation method)"
    echo -e "2) Install Whitelist System (NGINX, PHP, firewall, Fail2ban)"
    echo -e "3) Generate access URL with tokens"
    echo -e "4) Fix permissions"
    echo -e "5) Change Whitelist Password"
    echo -e "6) Check system status"
    echo -e "7) Uninstall everything (full wipe)"
    echo -e "8) Send whitelist link via Telegram"
    echo -e "9) Random FakeHtml"
    echo -e "M) Manage Telegram Users" # New option
    echo -e "A) Clean Old Whitelisted IPs"
    echo -e "C) Manage Cloudflare wildcard SSL certs"
    echo -e "T) Tor Installation"
    echo -e "0) Exit${NC}"
    echo -e "==========================================="

    read -p "Choose an option: " choice
    case $choice in
      1)
        check_root
        echo -e "${GREEN}Choose MTProto Proxy installation method:${NC}"
        echo "1) Method 1 Python Proxy by alexbers (git.io/fjo34 - Original)"
        echo "2) Method 2 @seriyps creator of the Erlang Proxy (git.io/fj5ru - Alternative)"
        read -p "Enter 1 or 2: " mtp_choice
        case "$mtp_choice" in
        1) install_mtproto_proxy ;;
        2) install_mtproto_proxy_method2 ;;
        *) echo -e "${RED}Invalid choice.${NC}" ;;
        esac
        ;;
      2)
        install_all
        ;;
      3)
        check_root
        generate_token_url
        ;;
      4)
        check_root
        fix_permissions
        ;;
      5)
        check_root
        create_password
        ;;
      6)
        check_root
        show_status
        ;;
      7)
        check_root
        uninstall
        ;;
      8)
        check_root
        send_whitelist_link_telegram
        ;;
      9)
        check_root
        random_template_site
        ;;
      M|m) # New option
        check_root
        manage_telegram_users_menu
        ;;
      A|a)
        check_root
        clean_old_whitelist_entries
        ;;
      C|c)
        check_root
        cloudflare_cert_menu 
        ;;
      T|t)
        check_root
        tor_menu
        ;;
        0)
        echo -e "${BLUE}Exiting...${NC}"
        exit 0
        ;;
      *)
        echo -e "${RED}Invalid option. Please try again.${NC}"
        ;;
    esac

    read -p "Press Enter to continue..."
  done
}

# ==============================================
# SCRIPT ENTRY POINT
# ==============================================

# Initialize logging
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

# Check if script is called with --clean-whitelist argument for cron job
if [[ "$#" -eq 1 && "$1" == "--clean-whitelist" ]]; then
    log "Script called for automated whitelist cleanup."
    clean_old_whitelist_entries
    exit 0
fi

# Check dependencies
check_dependencies

# Perform apt update here for fresh package lists before any installs
log "Updating package lists..."
apt update || error_exit "Failed to update package lists."

# Load any existing config
load_config

# Get PHP version
get_php_version

# First-time installation check
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "\n${BLUE}Welcome! It looks like this is your first time running the MTProto Proxy Whitelist Installer.${NC}"
    echo -e "${YELLOW}Please start by selecting option 2) Install Whitelist System to set up NGINX, PHP, and other components.${NC}\n"
    read -p "Press Enter to continue to the main menu..."
fi

# Start main menu
show_menu
