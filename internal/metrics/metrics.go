package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Provider owns the Prometheus registry and all BalanceDNS metrics.
// Labels are strictly bounded to avoid high-cardinality series:
//   - protocol  (udp|tcp|dot|doh)
//   - query_type (A|AAAA|CNAME|MX|NS|TXT|PTR|SOA|HTTPS|SVCB|OTHER)
//   - rcode    (NOERROR|NXDOMAIN|SERVFAIL|REFUSED|FORMERR|OTHER)
//   - upstream (stable configured name)
//   - plugin   (stable configured name)
//
// Never use domain, client IP, query id, or any random value as a label.
type Provider struct {
	registry *prometheus.Registry

	// DNS queries
	QueriesTotal    *prometheus.CounterVec
	QueriesInFlight prometheus.Gauge
	QueryDuration   *prometheus.HistogramVec
	ResponsesTotal  *prometheus.CounterVec

	// Cache
	CacheHitsTotal   prometheus.Counter
	CacheMissesTotal prometheus.Counter
	CacheEntries     prometheus.Gauge
	CacheEvictions   prometheus.Counter

	// Upstream
	UpstreamRequests *prometheus.CounterVec
	UpstreamErrors   *prometheus.CounterVec
	UpstreamTimeouts *prometheus.CounterVec
	UpstreamDuration *prometheus.HistogramVec
	UpstreamInFlight *prometheus.GaugeVec
	UpstreamHealth   *prometheus.GaugeVec

	// Plugins
	PluginRequests *prometheus.CounterVec
	PluginDuration *prometheus.HistogramVec
	PluginErrors   *prometheus.CounterVec

	// Supervisor
	ComponentUp       *prometheus.GaugeVec
	ComponentRestarts *prometheus.CounterVec
}

func New() *Provider {
	registry := prometheus.NewRegistry()

	p := &Provider{
		registry: registry,

		QueriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_queries_total",
			Help: "Total DNS queries received",
		}, []string{"protocol", "query_type"}),
		QueriesInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "balancedns_queries_in_flight",
			Help: "DNS queries currently being processed",
		}),
		QueryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "balancedns_query_duration_seconds",
			Help:    "DNS query processing duration",
			Buckets: []float64{0.0001, 0.0003, 0.001, 0.003, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1},
		}, []string{"protocol", "query_type", "rcode"}),
		ResponsesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_responses_total",
			Help: "DNS responses by rcode",
		}, []string{"rcode"}),

		CacheHitsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "balancedns_cache_hits_total",
			Help: "Total DNS cache hits",
		}),
		CacheMissesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "balancedns_cache_misses_total",
			Help: "Total DNS cache misses",
		}),
		CacheEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "balancedns_cache_entries",
			Help: "Current number of entries in the DNS cache",
		}),
		CacheEvictions: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "balancedns_cache_evictions_total",
			Help: "Total DNS cache evictions (LRU + expiry)",
		}),

		UpstreamRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_upstream_requests_total",
			Help: "Total requests sent to upstreams",
		}, []string{"upstream"}),
		UpstreamErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_upstream_errors_total",
			Help: "Total upstream request errors",
		}, []string{"upstream"}),
		UpstreamTimeouts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_upstream_timeouts_total",
			Help: "Total upstream request timeouts",
		}, []string{"upstream"}),
		UpstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "balancedns_upstream_duration_seconds",
			Help:    "Upstream DNS response latency",
			Buckets: []float64{0.001, 0.003, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2},
		}, []string{"upstream"}),
		UpstreamInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "balancedns_upstream_in_flight",
			Help: "Upstream requests currently in flight",
		}, []string{"upstream"}),
		UpstreamHealth: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "balancedns_upstream_health",
			Help: "Upstream health (1=healthy, 0=unhealthy)",
		}, []string{"upstream"}),

		PluginRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_plugin_requests_total",
			Help: "Total plugin invocations",
		}, []string{"plugin"}),
		PluginDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "balancedns_plugin_duration_seconds",
			Help:    "Plugin execution duration",
			Buckets: []float64{0.0001, 0.0003, 0.001, 0.003, 0.005, 0.01, 0.02, 0.05, 0.1},
		}, []string{"plugin"}),
		PluginErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_plugin_errors_total",
			Help: "Total plugin execution errors",
		}, []string{"plugin"}),

		ComponentUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "balancedns_component_up",
			Help: "Component running state (1=up, 0=down)",
		}, []string{"component"}),
		ComponentRestarts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "balancedns_component_restarts_total",
			Help: "Total component restarts by supervisor",
		}, []string{"component"}),
	}

	registry.MustRegister(
		p.QueriesTotal,
		p.QueriesInFlight,
		p.QueryDuration,
		p.ResponsesTotal,
		p.CacheHitsTotal,
		p.CacheMissesTotal,
		p.CacheEntries,
		p.CacheEvictions,
		p.UpstreamRequests,
		p.UpstreamErrors,
		p.UpstreamTimeouts,
		p.UpstreamDuration,
		p.UpstreamInFlight,
		p.UpstreamHealth,
		p.PluginRequests,
		p.PluginDuration,
		p.PluginErrors,
		p.ComponentUp,
		p.ComponentRestarts,
		// Standard Go runtime + process collectors (goroutines, memory, GC,
		// heap, CPU, process resources). No custom collectors needed.
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return p
}

func (p *Provider) Handler() http.Handler {
	return promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{})
}

// --- DNS query metrics ---

func (p *Provider) IncQueries(protocol, queryType string) {
	p.QueriesTotal.WithLabelValues(protocol, queryType).Inc()
}

func (p *Provider) IncQueriesInFlight() {
	p.QueriesInFlight.Inc()
}

func (p *Provider) DecQueriesInFlight() {
	p.QueriesInFlight.Dec()
}

func (p *Provider) ObserveQuery(protocol, queryType, rcode string, d time.Duration) {
	p.QueryDuration.WithLabelValues(protocol, queryType, rcode).Observe(d.Seconds())
}

func (p *Provider) IncResponse(rcode string) {
	p.ResponsesTotal.WithLabelValues(rcode).Inc()
}

// --- Cache metrics ---

func (p *Provider) IncCacheHits() {
	p.CacheHitsTotal.Inc()
}

func (p *Provider) IncCacheMisses() {
	p.CacheMissesTotal.Inc()
}

func (p *Provider) SetCacheEntries(n int) {
	p.CacheEntries.Set(float64(n))
}

func (p *Provider) IncCacheEvictions() {
	p.CacheEvictions.Inc()
}

// --- Upstream metrics ---

// UpstreamMetrics is a set of pre-resolved metric handles for a single
// upstream. Resolving handles once at startup avoids the per-request
// WithLabelValues map lookup, which is the dominant cost of upstream
// instrumentation on the hot path.
type UpstreamMetrics struct {
	Requests prometheus.Counter
	Errors   prometheus.Counter
	Timeouts prometheus.Counter
	Duration prometheus.Observer
	InFlight prometheus.Gauge
	Health   prometheus.Gauge
}

// UpstreamMetricsFor returns pre-resolved handles for the given upstream name.
// Call once at startup and reuse; do not call per request.
func (p *Provider) UpstreamMetricsFor(upstream string) *UpstreamMetrics {
	return &UpstreamMetrics{
		Requests: p.UpstreamRequests.WithLabelValues(upstream),
		Errors:   p.UpstreamErrors.WithLabelValues(upstream),
		Timeouts: p.UpstreamTimeouts.WithLabelValues(upstream),
		Duration: p.UpstreamDuration.WithLabelValues(upstream),
		InFlight: p.UpstreamInFlight.WithLabelValues(upstream),
		Health:   p.UpstreamHealth.WithLabelValues(upstream),
	}
}

func (p *Provider) IncUpstreamRequest(upstream string) {
	p.UpstreamRequests.WithLabelValues(upstream).Inc()
}

func (p *Provider) IncUpstreamError(upstream string) {
	p.UpstreamErrors.WithLabelValues(upstream).Inc()
}

func (p *Provider) IncUpstreamTimeout(upstream string) {
	p.UpstreamTimeouts.WithLabelValues(upstream).Inc()
}

func (p *Provider) ObserveUpstreamDuration(upstream string, d time.Duration) {
	p.UpstreamDuration.WithLabelValues(upstream).Observe(d.Seconds())
}

func (p *Provider) IncUpstreamInFlight(upstream string) {
	p.UpstreamInFlight.WithLabelValues(upstream).Inc()
}

func (p *Provider) DecUpstreamInFlight(upstream string) {
	p.UpstreamInFlight.WithLabelValues(upstream).Dec()
}

func (p *Provider) SetUpstreamHealth(upstream string, healthy bool) {
	if healthy {
		p.UpstreamHealth.WithLabelValues(upstream).Set(1)
		return
	}
	p.UpstreamHealth.WithLabelValues(upstream).Set(0)
}

// --- Plugin metrics ---

func (p *Provider) IncPluginRequest(plugin string) {
	p.PluginRequests.WithLabelValues(plugin).Inc()
}

func (p *Provider) ObservePluginDuration(plugin string, d time.Duration) {
	p.PluginDuration.WithLabelValues(plugin).Observe(d.Seconds())
}

func (p *Provider) IncPluginError(plugin string) {
	p.PluginErrors.WithLabelValues(plugin).Inc()
}

// --- Supervisor metrics ---

func (p *Provider) SetComponentUp(component string, up bool) {
	if up {
		p.ComponentUp.WithLabelValues(component).Set(1)
		return
	}
	p.ComponentUp.WithLabelValues(component).Set(0)
}

func (p *Provider) IncComponentRestart(component string) {
	p.ComponentRestarts.WithLabelValues(component).Inc()
}
