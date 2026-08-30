package router

import (
	"context"
	"net"
	"testing"

	"balancedns/internal/config"
	"balancedns/internal/metrics"

	"github.com/miekg/dns"
)

// startMockUpstream starts a local DNS server that answers A queries instantly.
func startMockUpstream(t testing.TB) string {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 1),
			})
		}
		_ = w.WriteMsg(resp)
	})
	srv := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.PacketConn = pc
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func benchForward(b *testing.B, withMetrics bool) {
	addr := startMockUpstream(b)
	var m *metrics.Provider
	if withMetrics {
		m = metrics.New()
	}
	r, err := NewResolver([]config.Upstream{
		{Name: "mock", Protocol: "udp", Addr: addr, Zones: []string{"."}, TimeoutMS: 1000},
	}, m)
	if err != nil {
		b.Fatal(err)
	}
	q := dns.Question{Name: "bench.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	req := new(dns.Msg)
	req.SetQuestion(q.Name, q.Qtype)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := r.Forward(context.Background(), req, q); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkForwardNoMetrics(b *testing.B)   { benchForward(b, false) }
func BenchmarkForwardWithMetrics(b *testing.B) { benchForward(b, true) }
