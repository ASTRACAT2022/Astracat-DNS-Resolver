package router

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"balancedns/internal/config"
	"balancedns/internal/metrics"

	"github.com/miekg/dns"
)

type Upstream struct {
	Name                  string
	Protocol              string
	Addr                  string
	DoHURL                string
	TLSServerName         string
	TLSInsecureSkipVerify bool
	Zones                 []string
	Timeout               time.Duration
	order                 int

	dnsClient *dns.Client
	tcpClient *dns.Client
	dohClient *http.Client

	// metrics holds pre-resolved metric handles for this upstream, avoiding
	// per-request WithLabelValues lookups on the hot path.
	metrics *metrics.UpstreamMetrics
}

type Resolver struct {
	upstreams []Upstream
	metrics   *metrics.Provider
}

func NewResolver(cfg []config.Upstream, m *metrics.Provider) (*Resolver, error) {
	if len(cfg) == 0 {
		return nil, errors.New("upstreams are required")
	}

	ups := make([]Upstream, 0, len(cfg))
	for i, u := range cfg {
		zones := make([]string, 0, len(u.Zones))
		for _, z := range u.Zones {
			zones = append(zones, normalizeZone(z))
		}

		up := Upstream{
			Name:                  u.Name,
			Protocol:              strings.ToLower(strings.TrimSpace(u.Protocol)),
			Addr:                  u.Addr,
			DoHURL:                u.DoHURL,
			TLSServerName:         u.TLSServerName,
			TLSInsecureSkipVerify: u.TLSInsecureSkipVerify,
			Zones:                 zones,
			Timeout:               time.Duration(u.TimeoutMS) * time.Millisecond,
			order:                 i,
		}
		if m != nil {
			up.metrics = m.UpstreamMetricsFor(u.Name)
		}

		switch up.Protocol {
		case "udp":
			up.dnsClient = newDNSClient("udp", up.Timeout, nil)
			up.tcpClient = newDNSClient("tcp", up.Timeout, nil)
		case "tcp":
			up.dnsClient = newDNSClient("tcp", up.Timeout, nil)
		case "dot":
			tlsConf := &tls.Config{InsecureSkipVerify: up.TLSInsecureSkipVerify}
			tlsConf.ServerName = selectTLSServerName(up.TLSServerName, up.Addr)
			up.dnsClient = newDNSClient("tcp-tls", up.Timeout, tlsConf)
		case "doh":
			transport := &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          256,
				MaxIdleConnsPerHost:   64,
				MaxConnsPerHost:       128,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   3 * time.Second,
				ExpectContinueTimeout: time.Second,
				DialContext: (&net.Dialer{
					Timeout:   minDuration(up.Timeout, 2*time.Second),
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: up.TLSInsecureSkipVerify,
					ServerName:         selectDoHServerName(up.TLSServerName, up.DoHURL),
					ClientSessionCache: tls.NewLRUClientSessionCache(128),
					MinVersion:         tls.VersionTLS12,
				},
			}
			up.dohClient = &http.Client{Timeout: up.Timeout, Transport: transport}
		default:
			return nil, fmt.Errorf("unsupported upstream protocol %q", up.Protocol)
		}

		ups = append(ups, up)
	}

	return &Resolver{upstreams: ups, metrics: m}, nil
}

func (r *Resolver) Forward(ctx context.Context, request *dns.Msg, q dns.Question) (*dns.Msg, Upstream, error) {
	candidates := r.selectCandidates(q.Name)
	if len(candidates) == 0 {
		return nil, Upstream{}, errors.New("no suitable upstream")
	}

	requestCopy := request.Copy()
	requestCopy.Question = []dns.Question{q}

	errs := make([]string, 0, len(candidates))
	for i := range candidates {
		up := candidates[i]
		resp, err := r.exchange(ctx, up, requestCopy)
		if err == nil && resp != nil {
			return resp, up, nil
		}
		if err == nil {
			err = errors.New("empty upstream response")
		}
		errs = append(errs, fmt.Sprintf("%s(%s): %v", up.Name, up.Protocol, err))
	}

	return nil, candidates[0], fmt.Errorf("all upstreams failed: %s", strings.Join(errs, "; "))
}

func (r *Resolver) exchange(parent context.Context, up Upstream, msg *dns.Msg) (*dns.Msg, error) {
	ctx := parent
	cancel := func() {}
	if up.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, up.Timeout)
	}
	defer cancel()

	m := up.metrics
	if m != nil {
		m.Requests.Inc()
		m.InFlight.Inc()
		defer m.InFlight.Dec()
	}

	var (
		resp *dns.Msg
		err  error
	)
	switch up.Protocol {
	case "udp":
		resp, err = r.exchangeDNS(ctx, up, msg, true)
	case "tcp", "dot":
		resp, err = r.exchangeDNS(ctx, up, msg, false)
	case "doh":
		resp, err = r.exchangeDoH(ctx, up, msg)
	default:
		err = fmt.Errorf("unsupported upstream protocol %q", up.Protocol)
	}

	if err != nil {
		if m != nil {
			m.Errors.Inc()
			m.Health.Set(0)
			if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				m.Timeouts.Inc()
			}
		}
		return nil, err
	}
	if m != nil {
		m.Health.Set(1)
	}
	return resp, nil
}

func (r *Resolver) exchangeDNS(ctx context.Context, up Upstream, msg *dns.Msg, tcpFallback bool) (*dns.Msg, error) {
	start := time.Now()
	resp, _, err := up.dnsClient.ExchangeContext(ctx, msg, up.Addr)
	if up.metrics != nil {
		up.metrics.Duration.Observe(time.Since(start).Seconds())
	}
	if err != nil {
		return nil, err
	}

	if tcpFallback && resp != nil && resp.Truncated {
		tcpStart := time.Now()
		resp, _, err = up.tcpClient.ExchangeContext(ctx, msg, up.Addr)
		if up.metrics != nil {
			up.metrics.Duration.Observe(time.Since(tcpStart).Seconds())
		}
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (r *Resolver) exchangeDoH(ctx context.Context, up Upstream, msg *dns.Msg) (*dns.Msg, error) {
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, up.DoHURL, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("build doh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	start := time.Now()
	resp, err := up.dohClient.Do(req)
	if up.metrics != nil {
		up.metrics.Duration.Observe(time.Since(start).Seconds())
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("doh http status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, fmt.Errorf("read doh response: %w", err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(payload); err != nil {
		return nil, fmt.Errorf("unpack doh dns message: %w", err)
	}
	return out, nil
}

func (r *Resolver) selectCandidates(qname string) []Upstream {
	fqdn := normalizeZone(qname)

	// Compute a score for each upstream: longest matching zone length, or 0
	// for a catch-all (no zones). Upstreams with no matching zone are skipped.
	scores := make([]int, len(r.upstreams))
	count := 0
	for i := range r.upstreams {
		up := r.upstreams[i]
		if len(up.Zones) == 0 {
			scores[i] = 0
			count++
			continue
		}
		best := -1
		for _, zone := range up.Zones {
			if zone == "." || strings.HasSuffix(fqdn, zone) {
				if len(zone) > best {
					best = len(zone)
				}
			}
		}
		if best >= 0 {
			scores[i] = best
			count++
		}
	}

	if count == 0 {
		return nil
	}

	// Sort matching upstream indices by (score desc, order asc).
	idx := make([]int, 0, count)
	for i := range r.upstreams {
		if scores[i] >= 0 {
			idx = append(idx, i)
		}
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ia, ib := idx[a], idx[b]
		if scores[ia] == scores[ib] {
			return r.upstreams[ia].order < r.upstreams[ib].order
		}
		return scores[ia] > scores[ib]
	})

	out := make([]Upstream, 0, count)
	for _, i := range idx {
		out = append(out, r.upstreams[i])
	}
	return out
}

func selectTLSServerName(cfgName, addr string) string {
	if strings.TrimSpace(cfgName) != "" {
		return cfgName
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func selectDoHServerName(cfgName, rawURL string) string {
	if strings.TrimSpace(cfgName) != "" {
		return cfgName
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func normalizeZone(z string) string {
	z = strings.TrimSpace(strings.ToLower(z))
	if z == "" {
		return "."
	}
	return dns.Fqdn(z)
}

func newDNSClient(network string, timeout time.Duration, tlsCfg *tls.Config) *dns.Client {
	dialTimeout := minDuration(timeout, 1200*time.Millisecond)
	return &dns.Client{
		Net:          network,
		Timeout:      timeout,
		DialTimeout:  dialTimeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		UDPSize:      1232,
		TLSConfig:    tlsCfg,
		Dialer: &net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		},
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// isTimeout reports whether err is a network timeout (net.Error with Timeout).
func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}
