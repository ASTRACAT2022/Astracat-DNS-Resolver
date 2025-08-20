# dns-g

This is a recursive DNS server written in Go, aiming for speed, performance, and stability. It supports both IPv4 and IPv6, includes retry logic with exponential backoff for external queries, and uses a simple in-memory cache.

## Features

*   **Recursive DNS Resolution:** Resolves domain names by querying authoritative DNS servers, starting from root servers.
*   **IPv4 & IPv6 Support:** Handles DNS queries and delegates resolution over both IPv4 and IPv6.
*   **Retry Logic:** Implements exponential backoff for retrying failed queries to upstream DNS servers, enhancing stability.
*   **DNS Caching:** Basic in-memory caching to speed up responses for frequently requested domains.
*   **UDP & TCP Support:** Listens for DNS queries on both UDP and TCP port 53.
*   **Systemd Service:** Can be installed and managed as a systemd service for persistent operation on Linux (Ubuntu).
*   **Configurable Port:** The listening port can be easily configured during installation.

## Deployment on Ubuntu

This guide will walk you through deploying the DNS server on an Ubuntu server using the provided `install.sh` script.

### Prerequisites

*   An Ubuntu server (e.g., Ubuntu 20.04 LTS or newer).
*   `sudo` privileges on the server.
*   `git` installed on the server (usually pre-installed).

### Installation Steps

1.  **Connect to your Ubuntu server via SSH:**

    ```bash
    ssh your_user@your_server_ip
    ```
    (Replace `your_user` with your username and `your_server_ip` with your server's IP address or hostname.)

2.  **Clone the repository:**

    Navigate to your desired directory (e.g., your home directory) and clone the `dns-g` repository:

    ```bash
    git clone https://github.com/ASTRACAT2022/dns-g.git
    cd dns-g
    ```

3.  **Make the installation script executable:**

    ```bash
    chmod +x install.sh
    ```

4.  **Run the installation script:**

    The `install.sh` script will perform the following actions:
    *   Check for and install Go (if not already present).
    *   Copy the server source files to `/opt/dns-g`.
    *   Download Go modules and build the `dns-server` executable.
    *   Set up and start the `dns-g-server` as a systemd service.

    You can run the script with or without a custom port:

    *   **To install on the default DNS port (53 UDP/TCP):**

        ```bash
        sudo ./install.sh
        ```

    *   **To install on a custom port (e.g., 5353 UDP/TCP):**

        ```bash
        sudo ./install.sh 5353
        ```
        (Replace `5353` with your desired port.)

### Post-Installation & Management

*   **Check Server Status:**

    To verify that the DNS server is running correctly as a systemd service:

    ```bash
    sudo systemctl status dns-g-server
    ```

*   **Stop the Server:**

    ```bash
    sudo systemctl stop dns-g-server
    ```

*   **Start the Server:**

    ```bash
    sudo systemctl start dns-g-server
    ```

*   **Restart the Server:**

    ```bash
    sudo systemctl restart dns-g-server
    ```

*   **Firewall Configuration (Important!):
**
    If your Ubuntu server has a firewall (e.g., UFW) enabled, you must open the port that your DNS server is listening on. For the default port 53, you would allow both UDP and TCP:

    ```bash
    sudo ufw allow 53/udp
    sudo ufw allow 53/tcp
    sudo ufw reload
    ```

    If you used a custom port (e.g., 5353), adjust the commands accordingly:

    ```bash
    sudo ufw allow 5353/udp
    sudo ufw allow 5353/tcp
    sudo ufw reload
    ```

*   **Configure Client Devices:**

    To use your new recursive DNS server, configure your client devices (computers, routers, etc.) to use your Ubuntu server's IP address as their primary DNS resolver.

## Build Instructions (For Development)

For local development or manual building, navigate to the project root directory and run:

```bash
/usr/local/go/bin/go build -o dns-server
```

This will create an executable file named `dns-server` in the current directory.

## Running Tests

To run the automated tests (requires Go installed locally):

```bash
/usr/local/go/bin/go test -v
```

## Updating the Server

To update the DNS server to the latest version from the GitHub repository, rebuild it, and restart the application, use the provided update scripts.

### Prerequisites for Updates

*   Ensure you are in the `dns-g` project directory.
*   The `update_code.sh` and `update_and_rebuild.sh` scripts must be present in the project root.

### Update Steps

1.  **Make the update scripts executable (if you haven't already):**

    ```bash
    chmod +x update_code.sh update_and_rebuild.sh
    ```

2.  **Run the update and rebuild script:**

    This script will:
    *   Pull the latest code from the `main` branch of the GitHub repository.
    *   Rebuild the Go application (`dns-g`).
    *   Start the `dns-g` application in the background.

    ```bash
    ./update_and_rebuild.sh
    ```

    After execution, you will see messages indicating the progress of the update, rebuild, and application start. A final message will confirm that the application is running the latest release.
