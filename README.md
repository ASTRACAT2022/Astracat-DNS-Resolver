# dns-g

This is a recursive DNS server written in Go, aiming for speed, performance, and stability.

## Build Instructions

To build the DNS server executable, navigate to the project root directory in your terminal and run:

```bash
/usr/local/go/bin/go build -o dns-server
```

This will create an executable file named `dns-server` in the current directory.

## Usage Instructions

To run the DNS server, execute the compiled binary:

```bash
./dns-server
```

The server will listen for DNS queries on UDP port 53. You can configure your system or network devices to use `127.0.0.1` (or the IP address of the machine running the server) as the DNS resolver.