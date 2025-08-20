package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // Import pprof package
	"os"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

// CacheEntry stores a full DNS message.
type CacheEntry struct {
	Msg        *dns.Msg
	Expiration time.Time
}

const (
	maxCnameChainLength = 5 // Maximum CNAME chain length to prevent infinite loops
)

// RateLimiter implements a token bucket algorithm for rate limiting.
type RateLimiter struct {
	tokens     int
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
	lastAccess time.Time // Add last access time
	mu         sync.Mutex
}

// NewRateLimiter creates a new RateLimiter instance.
func NewRateLimiter(maxTokens int, refillRate time.Duration) *RateLimiter {
	now := time.Now()
	return &RateLimiter{
		tokens:     maxTokens, // Start with a full bucket
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: now,
		lastAccess: now,
	}
}

// Allow checks if a request is allowed by the rate limiter.
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rl.lastAccess = now // Update last access time
	elapsed := now.Sub(rl.lastRefill)
	refillCount := int(elapsed / rl.refillRate)
	rl.tokens = min(rl.maxTokens, rl.tokens+refillCount)
	rl.lastRefill = now

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

var (
	Cache              *lru.Cache[string, *CacheEntry]
	clientRateLimiters = make(map[string]*RateLimiter)
	rateLimitMutex     sync.Mutex
)

// NsIpCacheEntry stores the resolved IP addresses for NS records.
type NsIpCacheEntry struct {
	IPs        []string
	Expiration time.Time
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	q := r.Question[0]
	clientIP := strings.Split(w.RemoteAddr().String(), ":")[0]

	rateLimitMutex.Lock()
	rl, ok := clientRateLimiters[clientIP]
	if !ok {
		// Initialize a new rate limiter for this client.
		// For example, allow 100 tokens, refill 1 token every 10ms (100 tokens/sec).
		rl = NewRateLimiter(100, 10*time.Millisecond)
		clientRateLimiters[clientIP] = rl
	}
	rateLimitMutex.Unlock()

	if !rl.Allow() {
		log.Printf("Rate limit exceeded for client IP %s", clientIP)
		m.SetRcode(r, dns.RcodeServerFailure) // Or dns.RcodeRefused
		w.WriteMsg(m)
		return
	}

	opt := r.IsEdns0()
	doBit := false
	if opt != nil {
		doBit = opt.Do()
	}

	// Check cache first
	cacheKey := fmt.Sprintf("%s:%d", q.Name, q.Qtype)
	if entry, ok := Cache.Get(cacheKey); ok && time.Now().Before(entry.Expiration) {
		log.Printf("Cache hit for %s", q.Name)
		m.Answer = entry.Msg.Answer
		m.Ns = entry.Msg.Ns
		m.Extra = entry.Msg.Extra
		w.WriteMsg(m)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolvedMsg, err := ResolveRecursive(ctx, q, doBit)
	if err != nil {
		log.Printf("Error resolving %s: %v", q.Name, err)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// Cache the successful response
	if resolvedMsg.Rcode == dns.RcodeSuccess {
		ttl := 3600 // Default TTL of 1 hour, can be adjusted
		if len(resolvedMsg.Answer) > 0 {
			ttl = int(resolvedMsg.Answer[0].Header().Ttl)
		}
		Cache.Add(cacheKey, &CacheEntry{
			Msg:        resolvedMsg,
			Expiration: time.Now().Add(time.Duration(ttl) * time.Second),
		})
	}

	m.Answer = resolvedMsg.Answer
	m.Ns = resolvedMsg.Ns
	m.Extra = resolvedMsg.Extra

	if opt != nil {
		// Respect client's UDP size, up to a reasonable maximum.
		udpsize := opt.UDPSize()
		if udpsize > 4096 {
			udpsize = 4096
		}
		m.SetEdns0(udpsize, doBit)
	}

	w.WriteMsg(m)
}

func main() {
	var err error
	Cache, err = lru.New[string, *CacheEntry](10000) // Initialize cache
	if err != nil {
		log.Fatalf("Failed to create cache: %v", err)
	}

	dnsPort := flag.String("port", "53", "Port to listen on")
	flag.Parse()

	// Use environment variable if set
	port := os.Getenv("DNS_PORT")
	if port != "" {
		*dnsPort = port
	}

	server := &dns.Server{Addr: ":" + *dnsPort, Net: "udp"}
	dns.HandleFunc(".", handleDnsRequest)
	server.Handler = dns.DefaultServeMux

	// Start pprof HTTP server
	go func() {
		log.Println("Starting pprof server on :6060")
		log.Fatal(http.ListenAndServe(":6060", nil))
	}()

	// Start a goroutine to clean up inactive rate limiters
	go cleanupRateLimiters(5*time.Minute, 10*time.Minute)

	log.Printf("Starting DNS server on :%s", *dnsPort)
	log.Fatal(server.ListenAndServe())
}

func ResolveRecursive(ctx context.Context, q dns.Question, doBit bool) (*dns.Msg, error) {
	return resolve(ctx, q, RootServers, doBit, 0)
}

func resolve(ctx context.Context, q dns.Question, servers []string, doBit bool, depth int) (*dns.Msg, error) {
	if depth > 10 {
		return nil, fmt.Errorf("max recursion depth exceeded")
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	r, _, err := queryServers(ctx, servers, q.Name, q.Qtype, doBit)
	if err != nil {
		return nil, fmt.Errorf("error querying servers for %s: %w", q.Name, err)
	}

	// If we have an answer, return it
	if r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
		// Handle CNAME chain
		if cname, ok := r.Answer[0].(*dns.CNAME); ok {
			if depth > maxCnameChainLength {
				return nil, fmt.Errorf("CNAME loop detected for %s", q.Name)
			}
			newQ := dns.Question{Name: cname.Target, Qtype: q.Qtype, Qclass: q.Qclass}
			return resolve(ctx, newQ, RootServers, doBit, depth+1)
		}
		return r, nil
	}

	// If we got NXDOMAIN, return it
	if r.Rcode == dns.RcodeNameError {
		return r, nil
	}

	// If we got a referral, follow it
	if r.Rcode == dns.RcodeSuccess && len(r.Answer) == 0 && len(r.Ns) > 0 {
		// Extract NS hostnames from the authority section
		nextServersHostnames := []string{}
		for _, ns := range r.Ns {
			if nsRec, ok := ns.(*dns.NS); ok {
				nextServersHostnames = append(nextServersHostnames, nsRec.Ns)
			}
		}

		if len(nextServersHostnames) == 0 {
			return r, nil // No delegation, return what we have (e.g., NODATA)
		}

		// Find IPs for these NS hostnames from glue records in the additional section
		nextServersIPs := []string{}
		for _, extra := range r.Extra {
			switch rec := extra.(type) {
			case *dns.A:
				for _, nsHost := range nextServersHostnames {
					if rec.Header().Name == nsHost {
						nextServersIPs = append(nextServersIPs, rec.A.String())
					}
				}
			case *dns.AAAA:
				for _, nsHost := range nextServersHostnames {
					if rec.Header().Name == nsHost {
						nextServersIPs = append(nextServersIPs, rec.AAAA.String())
					}
				}
			}
		}

		// If we don't have glue records, we need to resolve the NS hostnames
		if len(nextServersIPs) == 0 {
			for _, nsToResolve := range nextServersHostnames {
				// Resolve both A and AAAA records for the nameserver
				for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
					nsQ := dns.Question{Name: nsToResolve, Qtype: qtype, Qclass: dns.ClassINET}
					resolvedNs, err := resolve(ctx, nsQ, RootServers, doBit, depth+1)
					if err == nil {
						for _, ans := range resolvedNs.Answer {
							switch rec := ans.(type) {
							case *dns.A:
								nextServersIPs = append(nextServersIPs, rec.A.String())
							case *dns.AAAA:
								nextServersIPs = append(nextServersIPs, rec.AAAA.String())
							}
						}
					}
				}
			}
		}

		if len(nextServersIPs) == 0 {
			return nil, fmt.Errorf("could not find IP for authoritative servers %v", nextServersHostnames)
		}

		// Retry the original query with the new authoritative servers
		return resolve(ctx, q, nextServersIPs, doBit, depth+1)
	}

	// For other cases, return the response as is
	return r, nil
}

// Root servers (IPv4 and IPv6)
var RootServers = []string{
	// IPv4
	"198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10",
	"192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
	"193.0.14.129", "199.7.83.42", "202.12.27.33",
	// IPv6
	"2001:503:ba3e::2:30", "2001:500:200::b", "2001:500:2::c", "2001:500:2d::d",
	"2001:500:a8::e", "2001:500:2f::f", "2001:500:12::d0d", "2001:500:1::53",
	"2001:7fe::53", "2001:503:c27::2:30", "2001:7fd::1",
}

func cleanupRateLimiters(interval, maxIdle time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		rateLimitMutex.Lock()
		now := time.Now()
		for ip, rl := range clientRateLimiters {
			rl.mu.Lock()
			idleDuration := now.Sub(rl.lastAccess)
			rl.mu.Unlock()

			if idleDuration > maxIdle {
				log.Printf("Removing inactive rate limiter for %s", ip)
				delete(clientRateLimiters, ip)
			}
		}
		rateLimitMutex.Unlock()
	}
}

func queryServers(ctx context.Context, servers []string, name string, qtype uint16, doBit bool) (*dns.Msg, time.Duration, error) {
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 5 * time.Second
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	if doBit {
		m.SetEdns0(4096, true)
	}

	var wg sync.WaitGroup
	var result *dns.Msg
	var duration time.Duration
	var err error
	var mu sync.Mutex

	for _, server := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			start := time.Now()
			r, _, e := c.ExchangeContext(ctx, m, server+":53")
			elapsed := time.Since(start)
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				if result == nil || r.Rcode == dns.RcodeSuccess {
					result = r
					duration = elapsed
				}
			} else {
				if err == nil {
					err = e
				}
			}
		}(server)
	}

	wg.Wait()
	return result, duration, err
}
