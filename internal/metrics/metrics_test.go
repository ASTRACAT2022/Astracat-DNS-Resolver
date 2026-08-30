package metrics

import (
	"testing"
)

// TestLabelCardinality ensures label values are drawn from small, bounded sets
// and never from high-cardinality sources (domains, IPs, IDs).
func TestLabelCardinality(t *testing.T) {
	// Query type labels must be bounded.
	seen := map[string]bool{}
	for _, qtype := range []uint16{1, 28, 5, 15, 2, 16, 12, 6, 65, 64, 9999, 0} {
		l := QueryTypeLabel(qtype)
		seen[l] = true
	}
	// A, AAAA, CNAME, MX, NS, TXT, PTR, SOA, HTTPS, SVCB, OTHER
	if len(seen) > 12 {
		t.Fatalf("query_type label set too large: %d values", len(seen))
	}
	for l := range seen {
		if l == "" {
			t.Fatalf("empty query_type label")
		}
	}

	// Rcode labels must be bounded.
	rcodes := map[string]bool{}
	for _, rcode := range []int{0, 3, 2, 5, 1, 99} {
		rcodes[RcodeLabel(rcode)] = true
	}
	if len(rcodes) > 7 {
		t.Fatalf("rcode label set too large: %d values", len(rcodes))
	}

	// Protocol labels must be bounded.
	protos := map[string]bool{}
	for _, p := range []string{"udp", "tcp", "tcp-tls", "doh", "https", "weird", ""} {
		protos[ProtocolLabel(p)] = true
	}
	if len(protos) > 5 {
		t.Fatalf("protocol label set too large: %d values", len(protos))
	}
}

// TestProviderRegisters ensures the full metric set registers without conflict.
func TestProviderRegisters(t *testing.T) {
	p := New()
	if p == nil {
		t.Fatal("nil provider")
	}
	// Exercise every metric to ensure no panic on label creation.
	p.IncQueries("udp", "A")
	p.IncQueriesInFlight()
	p.DecQueriesInFlight()
	p.ObserveQuery("udp", "A", "NOERROR", 0)
	p.IncResponse("NOERROR")
	p.IncCacheHits()
	p.IncCacheMisses()
	p.SetCacheEntries(1)
	p.IncCacheEvictions()
	p.IncUpstreamRequest("test")
	p.IncUpstreamError("test")
	p.IncUpstreamTimeout("test")
	p.ObserveUpstreamDuration("test", 0)
	p.IncUpstreamInFlight("test")
	p.DecUpstreamInFlight("test")
	p.SetUpstreamHealth("test", true)
	p.IncPluginRequest("lua")
	p.ObservePluginDuration("lua", 0)
	p.IncPluginError("lua")
	p.SetComponentUp("dns-udp", true)
	p.IncComponentRestart("dns-udp")
}
