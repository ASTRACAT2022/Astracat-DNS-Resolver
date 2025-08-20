package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// getFreePort asks the kernel for a free open port that is ready to use.

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func TestWithDig(t *testing.T) {
	// Kill any lingering server processes to ensure a clean start
	exec.Command("pkill", "-f", "./dns-server").Run()
	time.Sleep(500 * time.Millisecond) // Give the OS a moment to release the port

	// 1. Build and run the DNS server as a separate process
	t.Logf("Building DNS server...")
	buildCmd := exec.Command("/usr/local/go/bin/go", "build", "-o", "dns-server")
	buildCmd.Dir = "."
	output, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build DNS server: %v\n%s", err, output)
	}

	port, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get a free port: %v", err)
	}
	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)

	t.Logf("Starting DNS server on %s...", serverAddr)
	cmd := exec.Command("./dns-server")
	cmd.Env = append(os.Environ(), "DNS_PORT="+strconv.Itoa(port)) // Set port via env var
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		t.Fatalf("Failed to start DNS server: %v", err)
	}

	// Ensure the server is shut down after tests
	defer func() {
		t.Logf("Stopping DNS server...")
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("Error killing DNS server process: %v", err)
		}
		cmd.Wait() // Wait for the process to exit
		t.Logf("DNS server stopped.")
	}()

	// Give the server some time to start up and check if it's listening
	time.Sleep(1 * time.Second) // Wait a bit longer for the server to be ready

	// 2. Run the dig-based test script
	t.Logf("Running dig test script...")
	testCmd := exec.Command("/bin/bash", "test.sh", strconv.Itoa(port))
	testCmd.Stdout = os.Stdout
	testCmd.Stderr = os.Stderr
	err = testCmd.Run()
	if err != nil {
		t.Fatalf("Dig test script failed: %v", err)
	}
}
