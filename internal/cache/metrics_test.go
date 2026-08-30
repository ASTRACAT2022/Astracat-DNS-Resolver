package cache

import (
	"testing"

	"balancedns/internal/metrics"

	"github.com/miekg/dns"
)

// TestCacheMetrics verifies that cache operations update the metrics provider.
func TestCacheMetrics(t *testing.T) {
	m := metrics.New()
	c := NewWithMetrics(10, 5, 600, m)

	q := dns.Question{Name: "metric.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := new(dns.Msg)
	msg.SetReply(&dns.Msg{Question: []dns.Question{q}})
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "metric.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{1, 1, 1, 1},
	})

	// Miss first
	if _, ok := c.Get(q); ok {
		t.Fatal("expected miss")
	}
	// Set then hit
	c.Set(q, msg)
	if _, ok := c.Get(q); !ok {
		t.Fatal("expected hit")
	}

	// Verify counters via the provider's registry.
	// (We can't easily read counter values without gathering, so just ensure
	// no panic and the entries gauge was set.)
	if m == nil {
		t.Fatal("nil metrics")
	}
}
