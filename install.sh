#!/bin/bash

set -e

# --- Configuration Variables ---
INSTALL_DIR="/opt/dns-g"
SERVICE_NAME="dns-g-server"
DEFAULT_PORT="5353"

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
    MIN_GO_VERSION="1.21"
    GO_INSTALL_PATH="/usr/local"
    GO_VERSION_TO_INSTALL="1.22.5" # You can update this to the latest stable version if needed
    GO_TAR_FILENAME="go${GO_VERSION_TO_INSTALL}.linux-amd64.tar.gz"
    GO_DOWNLOAD_URL="https://golang.org/dl/${GO_TAR_FILENAME}"

    CURRENT_GO_VERSION=""
    if command -v go &>/dev/null; then
        CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go is already installed: go version ${CURRENT_GO_VERSION}"
    fi

    # Function to compare versions (e.g., "1.19" < "1.21")
    version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

    if [ -z "$CURRENT_GO_VERSION" ] || version_gt "$MIN_GO_VERSION" "$CURRENT_GO_VERSION"; then
        if [ -z "$CURRENT_GO_VERSION" ]; then
            log_info "Go not found or too old. Installing Go ${GO_VERSION_TO_INSTALL}..."
        else
            log_info "Installed Go version ${CURRENT_GO_VERSION} is older than required ${MIN_GO_VERSION}. Upgrading to Go ${GO_VERSION_TO_INSTALL}..."
        fi

        # Remove any existing Go installation from /usr/local/go
        if [ -d "${GO_INSTALL_PATH}/go" ]; then
            log_info "Removing existing Go installation from ${GO_INSTALL_PATH}/go..."
            sudo rm -rf "${GO_INSTALL_PATH}/go"
        fi

        log_info "Downloading Go from ${GO_DOWNLOAD_URL}"
        wget -q --show-progress "${GO_DOWNLOAD_URL}"
        if [ $? -ne 0 ]; then
            log_error "Failed to download Go from ${GO_DOWNLOAD_URL}"
        fi

        log_info "Extracting Go to ${GO_INSTALL_PATH}"
        sudo tar -C "${GO_INSTALL_PATH}" -xzf "${GO_TAR_FILENAME}"
        if [ $? -ne 0 ]; then
            log_error "Failed to extract Go to ${GO_INSTALL_PATH}"
        fi

        log_info "Cleaning up downloaded tarball"
        rm "${GO_TAR_FILENAME}"

        # Add Go to PATH if not already there (for the current session and .bashrc for future sessions)
        if ! grep -q "${GO_INSTALL_PATH}/go/bin" ~/.bashrc; then
            log_info "Adding Go to PATH in ~/.bashrc"
            echo "export PATH=$PATH:${GO_INSTALL_PATH}/go/bin" >> ~/.bashrc
        fi
        export PATH=$PATH:${GO_INSTALL_PATH}/go/bin

        if ! command -v go &>/dev/null; then
            log_error "Go installation failed after script execution. Please check your PATH or install Go manually."
        fi
        log_info "Go ${GO_VERSION_TO_INSTALL} installed successfully: $(go version)"
    else
        log_info "Go version ${CURRENT_GO_VERSION} is already sufficient (>= ${MIN_GO_VERSION})."
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
    /usr/local/go/bin/go mod tidy
    popd

    log_info "Building DNS server..."
    pushd "$INSTALL_DIR"
    /usr/local/go/bin/go build -o dns-server
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
