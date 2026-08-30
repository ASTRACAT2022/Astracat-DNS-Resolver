package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// BenchmarkWithLabelValues measures the cost of per-call WithLabelValues lookup.
func BenchmarkWithLabelValues(b *testing.B) {
	p := New()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.IncUpstreamRequest("test")
		p.IncUpstreamInFlight("test")
		p.DecUpstreamInFlight("test")
		p.ObserveUpstreamDuration("test", 0)
		p.SetUpstreamHealth("test", true)
	}
}

// BenchmarkPreResolved measures the cost of pre-resolved metric handles.
func BenchmarkPreResolved(b *testing.B) {
	reg := prometheus.NewRegistry()
	req := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "req"}, []string{"upstream"})
	inflight := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "inflight"}, []string{"upstream"})
	dur := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "dur", Buckets: []float64{0.001, 0.01, 0.1, 1}}, []string{"upstream"})
	health := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "health"}, []string{"upstream"})
	reg.MustRegister(req, inflight, dur, health)

	// Pre-resolve handles once.
	reqH := req.WithLabelValues("test")
	inflightH := inflight.WithLabelValues("test")
	durH := dur.WithLabelValues("test")
	healthH := health.WithLabelValues("test")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reqH.Inc()
		inflightH.Inc()
		inflightH.Dec()
		durH.Observe(0)
		healthH.Set(1)
	}
}
