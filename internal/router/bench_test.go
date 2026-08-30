package router

import (
	"testing"

	"balancedns/internal/config"
	"balancedns/internal/metrics"
)

func BenchmarkSelectCandidates(b *testing.B) {
	r, err := NewResolver([]config.Upstream{
		{Name: "default", Protocol: "udp", Addr: "8.8.8.8:53", Zones: []string{"."}, TimeoutMS: 1000},
		{Name: "ru", Protocol: "udp", Addr: "77.88.8.8:53", Zones: []string{"ru."}, TimeoutMS: 1000},
		{Name: "deep", Protocol: "udp", Addr: "1.1.1.1:53", Zones: []string{"sub.ru."}, TimeoutMS: 1000},
	}, metrics.New())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.selectCandidates("www.sub.ru.")
	}
}
