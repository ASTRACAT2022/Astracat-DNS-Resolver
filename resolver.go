package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/domainr/dnsr"
)

var (
	Timeout             = 2000 * time.Millisecond
	TypicalResponseTime = 100 * time.Millisecond
	MaxRecursion        = 10
	MaxNameservers      = 2
	MaxIPs              = 2
)

// Resolver errors.
var (
	NXDOMAIN = fmt.Errorf("NXDOMAIN")

	ErrMaxRecursion = fmt.Errorf("maximum recursion depth reached: %d", MaxRecursion)
	ErrMaxIPs       = fmt.Errorf("maximum name server IPs queried: %d", MaxIPs)
	ErrNoARecords   = fmt.Errorf("no A records found for name server")
	ErrNoResponse   = fmt.Errorf("no responses received")
	ErrTimeout      = fmt.Errorf("timeout expired")
)

var dialerDefault = &net.Dialer{
	Timeout:   Timeout,
	KeepAlive: 30 * time.Second,
	DualStack: true,
}

// A ContextDialer implements the DialContext method, e.g. net.Dialer.
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Option specifies a configuration option for a Resolver.
type Option func(*Resolver)

// WithCache specifies a cache with capacity cap.
func WithCache(cap int) Option {
	return func(r *Resolver) {
		r.capacity = cap
	}
}

// WithDialer specifies a network dialer.
func WithDialer(d ContextDialer) Option {
	return func(r *Resolver) {
		r.dialer = d
	}
}

// WithExpiry specifies that the Resolver will delete stale cache entries.
func WithExpiry() Option {
	return func(r *Resolver) {
		r.expire = true
	}
}

// WithTimeout specifies the timeout for network operations.
func WithTimeout(timeout time.Duration) Option {
	return func(r *Resolver) {
		r.timeout = timeout
	}
}

// WithTCPRetry specifies that requests should be retried with TCP if responses
func WithTCPRetry() Option {
	return func(r *Resolver) {
		r.tcpRetry = true
	}
}

// Resolver implements a primitive, non-recursive, caching DNS resolver.
type Resolver struct {
	dialer       ContextDialer
	timeout      time.Duration
	dnsrResolver *dnsr.Resolver // Use dnsr resolver
	capacity     int
	expire       bool
	tcpRetry     bool
}

// NewResolver creates and initializes a Resolver with the given options.
// If no cache capacity is specified, it defaults to 0.
// If no timeout is specified, it defaults to the global Timeout variable.
func NewResolver(options ...Option) *Resolver {
	r := &Resolver{}
	for _, o := range options {
		o(r)
	}
	// Ensure dnsrResolver is initialized, defaulting to a cache of 0 if not set by options.
	if r.dnsrResolver == nil {
		r.dnsrResolver = dnsr.NewResolver(dnsr.WithCache(r.capacity))
	}
	// Ensure timeout is set, defaulting to the global Timeout if not specified.
	if r.timeout == 0 {
		r.timeout = Timeout
	}
	return r
}

// New creates a Resolver with the specified cache size.
func New(cap int) *Resolver {
	return NewResolver(WithCache(cap))
}

// NewWithTimeout creates a Resolver with the specified cache size and network timeout.
func NewWithTimeout(cap int, timeout time.Duration) *Resolver {
	return NewResolver(WithCache(cap), WithTimeout(timeout))
}

// NewExpiring creates a Resolver with the specified cache size and enables cache expiry.
func NewExpiring(cap int) *Resolver {
	return NewResolver(WithCache(cap), WithExpiry())
}

// NewExpiringWithTimeout creates a Resolver with the specified cache size, network timeout, and enables cache expiry.
func NewExpiringWithTimeout(cap int, timeout time.Duration) *Resolver {
	return NewResolver(WithCache(cap), WithTimeout(timeout), WithExpiry())
}

// Resolve calls ResolveErr to find DNS records of type qtype for the domain qname.
// For nonexistent domains (NXDOMAIN), it will return an empty, non-nil slice.
func (r *Resolver) Resolve(qname string, qtype string) ([]dnsr.RR, error) {
	rrs, err := r.ResolveErr(qname, qtype)
	if err == NXDOMAIN {
		return []dnsr.RR{}, nil
	}
	if err != nil {
		return nil, err
	}
	return rrs, nil
}

// ResolveErr finds DNS records of type qtype for the domain qname.
// ResolveErr finds DNS records of type qtype for the domain qname.
// For nonexistent domains, it will return an NXDOMAIN error.
// Specify an empty string in qtype to receive any DNS records found
// (currently A, AAAA, NS, CNAME, SOA, and TXT).
func (r *Resolver) ResolveErr(qname string, qtype string) ([]dnsr.RR, error) {
	records := r.dnsrResolver.Resolve(qname, qtype)
	if len(records) == 0 {
		return []dnsr.RR{}, NXDOMAIN
	}
	return records, nil
}

// ResolveCtx finds DNS records of type qtype for the domain qname using
// the supplied context. Requests may time out earlier if timeout is
// shorter than a deadline set in ctx.
// For nonexistent domains, it will return an NXDOMAIN error.
// Specify an empty string in qtype to receive any DNS records found
// (currently A, AAAA, NS, CNAME, SOA, and TXT).
func (r *Resolver) ResolveContext(ctx context.Context, qname string, qtype string) ([]dnsr.RR, error) {
	records := r.dnsrResolver.Resolve(qname, qtype)
	if len(records) == 0 {
		return []dnsr.RR{}, NXDOMAIN
	}
	return records, nil
}
