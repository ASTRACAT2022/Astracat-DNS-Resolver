package main

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func mockHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	q := r.Question[0]

	switch q.Name {
	case "example.com.":
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR("example.com. 3600 IN A 93.184.216.34")
			m.Answer = append(m.Answer, rr)
		}
	case "www.google.com.":
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR("www.google.com. 300 IN CNAME google.com.")
			m.Answer = append(m.Answer, rr)
			rr2, _ := dns.NewRR("google.com. 300 IN A 172.217.16.196")
			m.Answer = append(m.Answer, rr2)
		}
	case "google.com.":
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR("google.com. 300 IN A 172.217.16.196")
			m.Answer = append(m.Answer, rr)
		}
	case "www.example.org.":
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR("www.example.org. 3600 IN CNAME example.org.")
			m.Answer = append(m.Answer, rr)
			rr2, _ := dns.NewRR("example.org. 3600 IN A 93.184.216.34")
			m.Answer = append(m.Answer, rr2)
		}
	case "nonexistent.example.com.", "nonexistent-negative-cache.example.com.", "nonexistent-nodata.example.com.":
		m.Rcode = dns.RcodeNameError // NXDOMAIN
	}

	w.WriteMsg(m)
}

func startMockServer(t *testing.T) (string, func()) {
	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: dns.HandlerFunc(mockHandler)}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			t.Logf("Mock server ListenAndServe error: %v", err)
		}
	}()

	// Wait for the server to start
	// A more robust solution would be to use a channel or check the port.
	// For testing, a short sleep is often sufficient.
	<-time.After(100 * time.Millisecond)

	addr := server.PacketConn.LocalAddr().String()

	cleanup := func() {
		server.Shutdown()
	}

	return addr, cleanup
}
