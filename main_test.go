package main

import (
	"log"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSServer(t *testing.T) {
	// 1. Build and run the DNS server as a separate process
	log.Println("Building DNS server...")
	buildCmd := exec.Command("/usr/local/go/bin/go", "build", "-o", "dns-server")
	buildCmd.Dir = "."
	output, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build DNS server: %v\n%s", err, output)
	}

	log.Println("Starting DNS server...")
	cmd := exec.Command("./dns-server")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		t.Fatalf("Failed to start DNS server: %v", err)
	}

	// Ensure the server is shut down after tests
	defer func() {
		log.Println("Stopping DNS server...")
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("Error killing DNS server process: %v", err)
		}
		cmd.Wait() // Wait for the process to exit
		log.Println("DNS server stopped.")
	}()

	// Give the server some time to start up
	time.Sleep(2 * time.Second)

	// 2. Perform DNS queries against the running server
	localDNS := "127.0.0.1:53"
	client := new(dns.Client)

	tests := []struct {
		domain string
		qtype  uint16
		expectedAnswer string
	}{
		{"google.com.", dns.TypeA, ""},
		{"cloudflare.com.", dns.TypeA, ""},
		{"example.com.", dns.TypeA, ""},
		{"example.com.", dns.TypeTXT, ""}, // Test with a domain known to have TXT records
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(tt.domain), tt.qtype)
			
			log.Printf("Querying %s for %s (type %s)", localDNS, tt.domain, dns.Type(tt.qtype).String())
			r, _, err := client.Exchange(m, localDNS)
			if err != nil {
				t.Fatalf("Failed to exchange DNS query for %s: %v", tt.domain, err)
			}

			if r == nil || r.Rcode == dns.RcodeServerFailure || len(r.Answer) == 0 {
				t.Fatalf("No valid response or server failure for %s", tt.domain)
			}

			log.Printf("Received response for %s: %+v", tt.domain, r.Answer)
			// For simplicity, we are not asserting specific answers, just that we got one.
			// In a real test, you would parse r.Answer and verify its content.

			// If there's an expected answer, check it
			// No need to check for specific answers in the general case, just presence of an answer.
			// For TXT records, we should check if *any* TXT record is returned.
			if tt.qtype == dns.TypeTXT {
				foundTXT := false
				for _, ans := range r.Answer {
					if _, ok := ans.(*dns.TXT); ok {
						foundTXT = true
						break
					}
				}
				if !foundTXT {
					t.Errorf("Expected TXT answer not found for %s", tt.domain)
				}
			}
		})
	}

}
