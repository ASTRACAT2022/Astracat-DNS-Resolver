#!/bin/bash

set -e

# --- Configuration Variables ---
INSTALL_DIR="/opt/dns-g"
SERVICE_NAME="dns-g-server"
DEFAULT_PORT="53"

# --- Functions ---

log_info() {
    echo "[INFO] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
    exit 1
}

# --- Check and Install Go ---
install_go() {
    if command -v go &>/dev/null; then
        log_info "Go is already installed: $(go version)"
    else
        log_info "Go not found. Installing Go..."
        sudo apt update
        sudo apt install -y golang
        if ! command -v go &>/dev/null; then
            log_error "Go installation failed. Please install Go manually or check your system's package manager."
        fi
        log_info "Go installed successfully: $(go version)"
    fi
}

# --- Main Installation Logic ---
main() {
    log_info "Starting DNS Server Installation"

    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run this script with sudo or as root."
    fi

    install_go

    log_info "Creating installation directory $INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown "$USER":"$USER" "$INSTALL_DIR"

    log_info "Copying source files to $INSTALL_DIR"
    cp main.go go.mod go.sum "$INSTALL_DIR/"
    
    log_info "Changing to installation directory and fetching Go modules..."
    pushd "$INSTALL_DIR"
    go mod tidy
    popd

    log_info "Building DNS server..."
    pushd "$INSTALL_DIR"
    go build -o dns-server
    popd

    log_info "DNS server built successfully."

    # --- Configure Port ---
    PORT="$DEFAULT_PORT"
    if [ -n "$1" ]; then
        PORT="$1"
        log_info "Using custom port: $PORT"
    else
        log_info "Using default port: $DEFAULT_PORT (You can specify a port as an argument: ./install.sh <port>)"
    fi

    # --- Setup Systemd Service ---
    log_info "Setting up systemd service..."
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    
    sudo bash -c "cat > \"$SERVICE_FILE\"" <<EOF
[Unit]
Description=Recursive DNS Server
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/dns-server
Environment=DNS_PORT=${PORT}
WorkingDirectory=${INSTALL_DIR}
Restart=always
User=$USER
Group=$USER

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    sudo systemctl start "$SERVICE_NAME"

    log_info "DNS Server service enabled and started. It will now run on port $PORT."
    log_info "You can check its status with: sudo systemctl status $SERVICE_NAME"
    log_info "To stop: sudo systemctl stop $SERVICE_NAME"
    log_info "To restart: sudo systemctl restart $SERVICE_NAME"

    log_info "Installation complete!"
}

# Run the main function
main "$@"
