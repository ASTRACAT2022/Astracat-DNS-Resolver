#!/bin/bash

# --- Configuration Variables ---
INSTALL_DIR="/opt/dns-g"
SERVICE_NAME="dns-g-server"
DEFAULT_PORT="53"
MIN_GO_VERSION="1.21"
GO_INSTALL_PATH="/usr/local"
# Default Go version to install. Update this to the latest stable version if needed.
GO_VERSION_TO_INSTALL="1.22.5" 

# --- Functions ---

# Function to log informational messages
log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Function to log error messages and exit
log_error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
    exit 1
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to compare version strings (e.g., "1.19" < "1.21")
version_gt() { 
    test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; 
}

# --- Check and Install Go ---
install_go() {
    local current_go_version=""
    local go_arch=""

    # Determine architecture
    case "$(uname -m)" in
        x86_64) go_arch="amd64" ;;
        aarch64) go_arch="arm64" ;;
        *) log_error "Unsupported architecture: $(uname -m). Only amd64 and arm64 are supported." ;;
    esac

    local GO_TAR_FILENAME="go${GO_VERSION_TO_INSTALL}.linux-${go_arch}.tar.gz"
    local GO_DOWNLOAD_URL="https://golang.org/dl/${GO_TAR_FILENAME}"

    if command_exists go; then
        current_go_version=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go is already installed: go version ${current_go_version}"
    fi

    if [ -z "$current_go_version" ] || version_gt "$MIN_GO_VERSION" "$current_go_version"; then
        if [ -z "$current_go_version" ]; then
            log_info "Go not found or too old. Installing Go ${GO_VERSION_TO_INSTALL}..."
        else
            log_info "Installed Go version ${current_go_version} is older than required ${MIN_GO_VERSION}. Upgrading to Go ${GO_VERSION_TO_INSTALL}..."
        fi

        # Ensure curl is installed
        if ! command_exists curl; then
            log_error "curl is not installed. Please install curl to download Go."
        fi

        # Remove any existing Go installation from the target path to ensure a clean install
        if [ -d "${GO_INSTALL_PATH}/go" ]; then
            log_info "Removing existing Go installation from ${GO_INSTALL_PATH}/go..."
            # Use sudo for removal as it's in /usr/local
            if ! sudo rm -rf "${GO_INSTALL_PATH}/go"; then
                log_error "Failed to remove existing Go installation. Check permissions."
            fi
        fi

        log_info "Downloading Go ${GO_VERSION_TO_INSTALL} for linux-${go_arch} from ${GO_DOWNLOAD_URL}"
        if ! curl -L -o "/tmp/${GO_TAR_FILENAME}" "${GO_DOWNLOAD_URL}"; then
            log_error "Failed to download Go from ${GO_DOWNLOAD_URL}"
        fi

        log_info "Extracting Go to ${GO_INSTALL_PATH}"
        # Use sudo for extraction as it's in /usr/local
        if ! sudo tar -C "${GO_INSTALL_PATH}" -xzf "/tmp/${GO_TAR_FILENAME}"; then
            log_error "Failed to extract Go to ${GO_INSTALL_PATH}"
        fi

        log_info "Cleaning up downloaded tarball"
        rm "/tmp/${GO_TAR_FILENAME}"

        # Add Go to PATH for the current session and suggest for future sessions
        local go_bin_path="${GO_INSTALL_PATH}/go/bin"
        if ! echo "$PATH" | grep -q "$go_bin_path"; then
            export PATH=$PATH:$go_bin_path
            log_info "Added Go to PATH for the current session."
            
            # Suggest adding to shell profile
            local shell_profile=""
            if [ -n "$SHELL" ]; then
                case "$SHELL" in
                    */bash) shell_profile="$HOME/.bashrc" ;;
                    */zsh) shell_profile="$HOME/.zshrc" ;;
                    *) shell_profile="$HOME/.profile" ;; # Fallback
                esac
            else
                shell_profile="$HOME/.profile" # Fallback if SHELL is not set
            fi

            if ! grep -q "export PATH=.*${go_bin_path}" "$shell_profile"; then
                log_info "Adding Go to PATH in ${shell_profile} for future sessions."
                echo "" >> "$shell_profile"
                echo "# Added by DNS Server installer" >> "$shell_profile"
                echo "export PATH=\$PATH:${go_bin_path}" >> "$shell_profile"
            else
                log_info "Go PATH already exists in ${shell_profile}."
            fi
        else
            log_info "Go binary path is already in the current session's PATH."
        fi

        # Verify installation
        if ! command_exists go; then
            log_error "Go installation failed. Please check your PATH or install Go manually."
        fi
        log_info "Go ${GO_VERSION_TO_INSTALL} installed successfully: $(go version)"
    else
        log_info "Go version ${current_go_version} is already sufficient (>= ${MIN_GO_VERSION})."
    fi
}

# Function to validate port number
validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        log_error "Invalid port number: '$port'. Port must be a number."
    fi
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        log_error "Invalid port number: '$port'. Port must be between 1 and 65535."
    fi
}

# --- Main Installation Logic ---
main() {
    log_info "Starting DNS Server Installation"

    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run this script with sudo or as root."
    fi

    # Determine the directory where the script is located
    local script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

    # Install Go if necessary
    install_go

    # --- Create Installation Directory ---
    log_info "Creating installation directory: $INSTALL_DIR"
    if ! sudo mkdir -p "$INSTALL_DIR"; then
        log_error "Failed to create installation directory: $INSTALL_DIR. Check permissions."
    fi
    # Set ownership to the user who invoked sudo, if available, otherwise root.
    local owner_user=${SUDO_USER:-root}
    if ! sudo chown "$owner_user":"$owner_user" "$INSTALL_DIR"; then
        log_error "Failed to set ownership for $INSTALL_DIR. Check permissions."
    fi

    # --- Copy Source Files ---
    log_info "Copying source files to $INSTALL_DIR"
    # Ensure we are copying from the script's directory
    if ! sudo cp "${script_dir}/main.go" "${script_dir}/go.mod" "${script_dir}/go.sum" "$INSTALL_DIR/"; then
        log_error "Failed to copy source files to $INSTALL_DIR. Ensure main.go, go.mod, and go.sum are in the same directory as the script."
    fi
    
    # --- Fetch Go Modules and Build ---
    log_info "Changing to installation directory and fetching Go modules..."
    pushd "$INSTALL_DIR" > /dev/null
    if ! /usr/local/go/bin/go mod tidy; then
        log_error "Failed to run 'go mod tidy' in $INSTALL_DIR."
    fi
    popd > /dev/null

    log_info "Building DNS server..."
    pushd "$INSTALL_DIR" > /dev/null
    # Use the Go binary from the expected installation path
    if ! /usr/local/go/bin/go build -o dns-server; then
        log_error "Failed to build the DNS server in $INSTALL_DIR."
    fi
    popd > /dev/null

    log_info "DNS server built successfully."

    # --- Configure Port ---
    local PORT="$DEFAULT_PORT"
    if [ -n "$1" ]; then
        validate_port "$1"
        PORT="$1"
        log_info "Using custom port: $PORT"
    else
        log_info "Using default port: $DEFAULT_PORT. You can specify a port as an argument: sudo $0 <port>"
    fi

    # --- Setup Systemd Service ---
    log_info "Setting up systemd service for ${SERVICE_NAME}..."
    local SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    
    # Determine the user for the service. Use SUDO_USER if available, otherwise root.
    local service_user=${SUDO_USER:-root}
    log_info "Configuring service to run as user: $service_user"

    # Create the systemd service file
    local service_content="[Unit]
Description=Recursive DNS Server
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/dns-server
Environment=DNS_PORT=${PORT}
WorkingDirectory=${INSTALL_DIR}
Restart=always
User=${service_user}
Group=${service_user}

[Install]
WantedBy=multi-user.target
"
    # Use sudo to write to /etc/systemd/system
    if ! echo "$service_content" | sudo tee "$SERVICE_FILE" > /dev/null; then
        log_error "Failed to write systemd service file to $SERVICE_FILE. Check permissions."
    fi

    log_info "Reloading systemd daemon..."
    if ! sudo systemctl daemon-reload; then
        log_error "Failed to reload systemd daemon."
    fi

    log_info "Enabling ${SERVICE_NAME} service..."
    if ! sudo systemctl enable "$SERVICE_NAME"; then
        log_error "Failed to enable ${SERVICE_NAME} service."
    fi

    log_info "Starting ${SERVICE_NAME} service..."
    if ! sudo systemctl start "$SERVICE_NAME"; then
        log_error "Failed to start ${SERVICE_NAME} service. Check status with 'sudo systemctl status ${SERVICE_NAME}'."
    fi

    log_info "DNS Server service enabled and started. It will now run on port $PORT."
    log_info "You can check its status with: sudo systemctl status $SERVICE_NAME"
    log_info "To stop: sudo systemctl stop $SERVICE_NAME"
    log_info "To restart: sudo systemctl restart $SERVICE_NAME"

    log_info "Installation complete!"
}

# --- Script Execution ---
# Check if the script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Execute the main function, passing any command-line arguments
    main "$@"
fi
