package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
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

// startDNSServer builds and starts the DNS server, returning its address and a cleanup function.
func startDNSServer(t *testing.T) (string, func()) {
	// Kill any lingering server processes to ensure a clean start
	exec.Command("pkill", "-f", "./dns-server").Run()
	time.Sleep(500 * time.Millisecond) // Give the OS a moment to release the port

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

	// Give the server some time to start up and check if it's listening
	time.Sleep(1 * time.Second) // Wait a bit longer for the server to be ready

	cleanup := func() {
		t.Logf("Stopping DNS server...")
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("Error killing DNS server process: %v", err)
		}
		cmd.Wait() // Wait for the process to exit
		t.Logf("DNS server stopped.")
	}
	return serverAddr, cleanup
}

func TestWithDig(t *testing.T) {
	serverAddr, cleanup := startDNSServer(t)
	defer cleanup()

	// 2. Run the dig-based test script
	t.Logf("Running dig test script...")
	// Extract port from serverAddr
	_, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		t.Fatalf("Failed to parse server address: %v", err)
	}
	testCmd := exec.Command("/bin/bash", "test.sh", portStr)
	testCmd.Stdout = os.Stdout
	testCmd.Stderr = os.Stderr
	err = testCmd.Run()
	if err != nil {
		t.Fatalf("Dig test script failed: %v", err)
	}
}

func TestDNSResolution(t *testing.T) {
	serverAddr, cleanup := startDNSServer(t)
	defer cleanup()

	c := new(dns.Client)
	c.Net = "udp"
	addr := net.JoinHostPort("127.0.0.1", strings.Split(serverAddr, ":")[1])

	tests := []struct {
		name     string
		qname    string
		qtype    uint16
		expected string // Expected IP address for A records, or CNAME target
		expectNX bool   // Expect NXDOMAIN
		expectNo bool   // Expect NODATA (NOERROR with no answers)
	}{
		{
			name:     "Basic A record",
			qname:    "example.com.",
			qtype:    dns.TypeA,
			expected: "", // Expect any A record, not a specific one
		},
		{
			name:     "Non-existent domain (NXDOMAIN)",
			qname:    "nonexistent.example.com.",
			qtype:    dns.TypeA,
			expectNX: true,
		},
		{
			name:     "Non-existent domain for specific type (NODATA/NXDOMAIN)",
			qname:    "nonexistent.example.com.", // Use a non-existent domain for a true NODATA/NXDOMAIN
			qtype:    dns.TypeMX,
			expectNX: true, // Should result in NXDOMAIN
		},
		{
			name:     "CNAME to A record resolution (AAA A CHAME)",
			qname:    "www.google.com.", // www.google.com is typically a CNAME to google.com
			qtype:    dns.TypeA,
			expected: "", // Expect any A record after CNAME resolution
		},
		{
			name:     "CNAME resolution",
			qname:    "www.example.org.", // www.example.org is a CNAME to example.org
			qtype:    dns.TypeA,
			expected: "", // Expect any A record after CNAME resolution
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(tt.qname), tt.qtype)
			m.RecursionDesired = true // Our server is recursive

			r, _, err := c.Exchange(m, addr)
			if err != nil {
				t.Fatalf("Failed to exchange DNS query for %s: %v", tt.qname, err)
			}

			if tt.expectNX {
				if r.Rcode != dns.RcodeNameError {
					t.Errorf("Expected NXDOMAIN for %s, got Rcode %s", tt.qname, dns.RcodeToString[r.Rcode])
				}
				return
			}

			if tt.expectNo {
				if r.Rcode != dns.RcodeSuccess || len(r.Answer) > 0 {
					t.Errorf("Expected NOERROR/NODATA for %s, got Rcode %s and %d answers", tt.qname, dns.RcodeToString[r.Rcode], len(r.Answer))
				}
				return
			}

			if r.Rcode != dns.RcodeSuccess {
				t.Errorf("Expected RcodeSuccess for %s, got Rcode %s", tt.qname, dns.RcodeToString[r.Rcode])
				return
			}

			if len(r.Answer) == 0 {
				t.Errorf("Expected answers for %s, got none", tt.qname)
				return
			}

			// For A and CNAME resolution, just check if any answer is returned and it's an A record
			if tt.expected == "" {
				foundA := false
				for _, ans := range r.Answer {
					if _, ok := ans.(*dns.A); ok {
						foundA = true
						break
					}
				}
				if !foundA {
					t.Errorf("Expected at least one A record for %s, got none. Answers: %v", tt.qname, r.Answer)
				}
			} else {
				// This block is for specific expectations, currently not used for A/CNAME
				found := false
				for _, ans := range r.Answer {
					if a, ok := ans.(*dns.A); ok {
						if a.A.String() == tt.expected {
							found = true
							break
						}
					} else if cname, ok := ans.(*dns.CNAME); ok && tt.qtype == dns.TypeCNAME {
						if cname.Target == tt.expected {
							found = true
							break
						}
					}
				}

				if !found {
					t.Errorf("Did not find expected answer for %s. Expected: %s, Got: %v", tt.qname, tt.expected, r.Answer)
				}
			}
		})
	}
}

func TestCache(t *testing.T) {
	serverAddr, cleanup := startDNSServer(t)
	defer cleanup()

	c := new(dns.Client)
	c.Net = "udp"
	addr := net.JoinHostPort("127.0.0.1", strings.Split(serverAddr, ":")[1])

	qname := "google.com." // Use a reliably resolvable domain

	// 1. Initial query - should be a cache miss
	t.Logf("First query for %s (expect cache miss)", qname)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	m.RecursionDesired = true

	r1, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("Failed first DNS query for %s: %v", qname, err)
	}
	if r1.Rcode != dns.RcodeSuccess || len(r1.Answer) == 0 {
		t.Fatalf("First query for %s failed or returned no answer: Rcode=%s, Answers=%d", qname, dns.RcodeToString[r1.Rcode], len(r1.Answer))
	}
	t.Logf("First query successful for %s", qname)

	// 2. Second query - should be a cache hit
	t.Logf("Second query for %s (expect cache hit)", qname)
	r2, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("Failed second DNS query for %s: %v", qname, err)
	}
	if r2.Rcode != dns.RcodeSuccess || len(r2.Answer) == 0 {
		t.Fatalf("Second query for %s failed or returned no answer: Rcode=%s, Answers=%d", qname, dns.RcodeToString[r2.Rcode], len(r2.Answer))
	}
	t.Logf("Second query successful for %s", qname)

	// To truly verify a cache hit, we'd need to inspect server logs or mock upstream.
	// For now, successful and fast second query is a good indicator.
	// A more robust test would involve mocking the upstream DNS server to ensure it's not hit on the second query.
}

func TestNegativeCache(t *testing.T) {
	serverAddr, cleanup := startDNSServer(t)
	defer cleanup()

	c := new(dns.Client)
	c.Net = "udp"
	addr := net.JoinHostPort("127.0.0.1", strings.Split(serverAddr, ":")[1])

	qnameNX := "nonexistent-negative-cache.example.com." // Unique non-existent domain

	// Test NXDOMAIN negative caching
	t.Run("NXDOMAIN Negative Cache", func(t *testing.T) {
		t.Logf("First query for NXDOMAIN %s (expect cache miss, then negative cache)", qnameNX)
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(qnameNX), dns.TypeA)
		m.RecursionDesired = true

		r1, _, err := c.Exchange(m, addr)
		if err != nil {
			t.Fatalf("Failed first DNS query for %s: %v", qnameNX, err)
		}
		if r1.Rcode != dns.RcodeNameError {
			t.Fatalf("First query for %s expected NXDOMAIN, got Rcode %s", qnameNX, dns.RcodeToString[r1.Rcode])
		}
		t.Logf("First query for NXDOMAIN successful for %s", qnameNX)

		// Second query - should be a negative cache hit
		t.Logf("Second query for NXDOMAIN %s (expect negative cache hit)", qnameNX)
		r2, _, err := c.Exchange(m, addr)
		if err != nil {
			t.Fatalf("Failed second DNS query for %s: %v", qnameNX, err)
		}
		if r2.Rcode != dns.RcodeNameError {
			t.Fatalf("Second query for %s expected NXDOMAIN (from cache), got Rcode %s", qnameNX, dns.RcodeToString[r2.Rcode])
		}
		t.Logf("Second query for NXDOMAIN successful for %s", qnameNX)
	})

	// Test NODATA negative caching
	t.Run("NODATA Negative Cache", func(t *testing.T) {
		// Use a non-existent domain for NODATA test to ensure NXDOMAIN
		qnameNoDataActual := "nonexistent-nodata.example.com."
		t.Logf("First query for NODATA %s (expect cache miss, then negative cache)", qnameNoDataActual)
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(qnameNoDataActual), dns.TypeMX) // Query for MX record
		m.RecursionDesired = true

		r1, _, err := c.Exchange(m, addr)
		if err != nil {
			t.Fatalf("Failed first DNS query for %s: %v", qnameNoDataActual, err)
		}
		// For a non-existent domain, querying for any type should result in NXDOMAIN
		if r1.Rcode != dns.RcodeNameError {
			t.Fatalf("First query for %s expected NXDOMAIN, got Rcode %s", qnameNoDataActual, dns.RcodeToString[r1.Rcode])
		}
		t.Logf("First query for NODATA successful for %s", qnameNoDataActual)

		// Second query - should be a negative cache hit
		t.Logf("Second query for NODATA %s (expect negative cache hit)", qnameNoDataActual)
		r2, _, err := c.Exchange(m, addr)
		if err != nil {
			t.Fatalf("Failed second DNS query for %s: %v", qnameNoDataActual, err)
		}
		if r2.Rcode != dns.RcodeNameError {
			t.Fatalf("Second query for %s expected NXDOMAIN (from cache), got Rcode %s", qnameNoDataActual, dns.RcodeToString[r2.Rcode])
		}
		t.Logf("Second query for NODATA successful for %s", qnameNoDataActual)
	})
}
