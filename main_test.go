package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestResolveQuestion(t *testing.T) {
	// Test cases
	tests := []struct {
		name        string
		qname       string
		qtype       uint16
		expectedLen int
		expectError bool
	}{
		{
			name:        "A record for google.com",
			qname:       "google.com.",
			qtype:       dns.TypeA,
			expectedLen: 1, // Expecting at least one A record
			expectError: false,
		},
		{
			name:        "AAAA record for google.com",
			qname:       "google.com.",
			qtype:       dns.TypeAAAA,
			expectedLen: 1, // Expecting at least one AAAA record
			expectError: false,
		},
		{
			name:        "MX record for google.com",
			qname:       "google.com.",
			qtype:       dns.TypeMX,
			expectedLen: 1, // Expecting at least one MX record
			expectError: false,
		},
		{
			name:        "NS record for google.com",
			qname:       "google.com.",
			qtype:       dns.TypeNS,
			expectedLen: 1, // Expecting at least one NS record
			expectError: false,
		},
		{
			name:        "CNAME record for www.google.com",
			qname:       "www.google.com.",
			qtype:       dns.TypeCNAME,
			expectedLen: 1, // Expecting at least one CNAME record
			expectError: false,
		},
		{
			name:        "TXT record for google.com",
			qname:       "google.com.",
			qtype:       dns.TypeTXT,
			expectedLen: 1, // Expecting at least one TXT record
			expectError: false,
		},
		{
			name:        "Non-existent domain",
			qname:       "nonexistent.example.",
			qtype:       dns.TypeA,
			expectedLen: 0,
			expectError: true,
		},
		{
			name:        "Invalid query type",
			qname:       "google.com.",
			qtype:       dns.TypeSOA, // SOA is not directly resolvable
			expectedLen: 0,
			expectError: true,
		},
	}

	// Resolver уже инициализирован в init() функции main.go

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := dns.Question{
				Name:   tt.qname,
				Qtype:  tt.qtype,
				Qclass: dns.ClassINET,
			}
			answers, err := resolveQuestion(q)

			if tt.expectError && err == nil {
				t.Errorf("Expected error, but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectError {
				if len(answers) < tt.expectedLen {
					t.Errorf("Expected at least %d answers, got %d", tt.expectedLen, len(answers))
				}
				// Further checks can be added here, e.g., checking the content of the answers
				for _, answer := range answers {
					switch rr := answer.(type) {
					case *dns.A:
						if net.ParseIP(rr.A.String()) == nil {
							t.Errorf("Invalid A record: %s", rr.A.String())
						}
					case *dns.AAAA:
						if net.ParseIP(rr.AAAA.String()) == nil {
							t.Errorf("Invalid AAAA record: %s", rr.AAAA.String())
						}
					case *dns.MX:
						if rr.Mx == "" {
							t.Errorf("Invalid MX record: %s", rr.Mx)
						}
					case *dns.NS:
						if rr.Ns == "" {
							t.Errorf("Invalid NS record: %s", rr.Ns)
						}
					case *dns.CNAME:
						if rr.Target == "" {
							t.Errorf("Invalid CNAME record: %s", rr.Target)
						}
					case *dns.TXT:
						if len(rr.Txt) == 0 {
							t.Errorf("Invalid TXT record: %v", rr.Txt)
						}
					}
				}
			}
		})
	}
}
