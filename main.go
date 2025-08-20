package main

import (
	"context"
	"fmt"
	"log"
	rand "math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2" // Import for LRU cache
	"github.com/miekg/dns"
)

const maxCacheSize = 10000
const maxRetries = 5
const initialTimeout = 2 * time.Second

const (
	rateLimitWindow     = 1 * time.Second // Time window for rate limiting
	maxQueriesPerWindow = 100             // Max queries allowed per client IP within the window
)

var (
	Cache *lru.Cache[string, CacheEntry] // LRU cache with string key (normalized name)

	CacheMutex sync.RWMutex // Still needed for overall cache access

	// Rate limiting
	clientQueryCounts     = make(map[string]int)
	clientQueryTimestamps = make(map[string]time.Time)
	rateLimitMutex        sync.Mutex
)

type CacheEntry struct {
	Msg        *dns.Msg
	Expiration time.Time
}

// NegativeCacheEntry stores negative responses (NXDOMAIN/NODATA)
type NegativeCacheEntry struct {
	Msg        *dns.Msg
	Expiration time.Time
}

var NegativeCache *lru.Cache[string, NegativeCacheEntry] // LRU cache for negative responses

var RootServers = []string{
	"198.41.0.4:53",          // A.ROOT-SERVERS.NET (IPv4)
	"2001:503:ba3e::2:30:53", // A.ROOT-SERVERS.NET (IPv6)
	"170.247.170.2:53",       // B.ROOT-SERVERS.NET (IPv4)
	"2801:1b8:10::b:53",      // B.ROOT-SERVERS.NET (IPv6)
	"192.33.4.12:53",         // C.ROOT-SERVERS.NET (IPv4)
	"2001:500:2::c:53",       // C.ROOT-SERVERS.NET (IPv6)
	"199.7.91.13:53",         // D.ROOT-SERVERS.NET (IPv4)
	"2001:500:2d::d:53",      // D.ROOT-SERVERS.NET (IPv6)
	"192.203.230.10:53",      // E.ROOT-SERVERS.NET (IPv4)
	"2001:500:a8::e:53",      // E.ROOT-SERVERS.NET (IPv6)
	"192.5.5.241:53",         // F.ROOT-SERVERS.NET (IPv4)
	"2001:500:2f::f:53",      // F.ROOT-SERVERS.NET (IPv6)
	"192.112.36.4:53",        // G.ROOT-SERVERS.NET (IPv4)
	"2001:500:12::d0d:53",    // G.ROOT-SERVERS.NET (IPv6)
	"198.97.190.53:53",       // H.ROOT-SERVERS.NET (IPv4)
	"2001:500:1::53:53",      // H.ROOT-SERVERS.NET (IPv6)
	"192.36.148.17:53",       // I.ROOT-SERVERS.NET (IPv4)
	"2001:7fe::53:53",        // I.ROOT-SERVERS.NET (IPv6)
	"192.58.128.30:53",       // J.ROOT-SERVERS.NET (IPv4)
	"2001:503:c27::2:30:53",  // J.ROOT-SERVERS.NET (IPv6)
	"193.0.14.129:53",        // K.ROOT-SERVERS.NET (IPv4)
	"2001:7fd::1:53",         // K.ROOT-SERVERS.NET (IPv6)
	"199.7.83.42:53",         // L.ROOT-SERVERS.NET (IPv4)
	"2001:500:9f::42:53",     // L.ROOT-SERVERS.NET (IPv6)
	"202.12.27.33:53",        // M.ROOT-SERVERS.NET (IPv4)
	"2001:dc3::35:53",        // M.ROOT-SERVERS.NET (IPv6)
}

const globalResolutionTimeout = 10 * time.Second // Overall timeout for a single DNS resolution

func ResolveDNS(ctx context.Context, q dns.Question, doBit bool) (*dns.Msg, error) {
	log.Printf("Resolving %s (context timeout: %v)", q.Name, globalResolutionTimeout)

	normalizedQName := dns.Fqdn(strings.ToLower(q.Name))

	// Check positive cache
	CacheMutex.RLock()
	if entry, ok := Cache.Get(normalizedQName); ok && time.Now().Before(entry.Expiration) {
		CacheMutex.RUnlock()
		log.Printf("Positive cache hit for %s", q.Name)
		return entry.Msg, nil
	}
	CacheMutex.RUnlock()

	// Check negative cache
	CacheMutex.RLock()
	if negEntry, ok := NegativeCache.Get(normalizedQName); ok && time.Now().Before(negEntry.Expiration) {
		CacheMutex.RUnlock()
		log.Printf("Negative cache hit for %s: returning cached NXDOMAIN/NODATA", q.Name)
		return negEntry.Msg, nil
	}
	CacheMutex.RUnlock()

	log.Printf("Cache miss for %s. Starting recursive resolution.", q.Name)

	var (
		resp *dns.Msg
		err  error
	)

	for i := 0; i < maxRetries; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err() // Propagate context cancellation
		default:
		}

		resp, err = ResolveRecursive(ctx, q, doBit)
		if err == nil {
			return resp, nil
		}
		log.Printf("Recursive resolution for %s failed (attempt %d/%d): %v. Retrying...", q.Name, i+1, maxRetries, err)
		time.Sleep(initialTimeout * time.Duration(1<<i)) // Exponential backoff
	}

	return nil, fmt.Errorf("failed to resolve %s after %d retries: %v", q.Name, maxRetries, err)
}

func ResolveRecursive(ctx context.Context, q dns.Question, doBit bool) (*dns.Msg, error) {
	servers := RootServers
	originalQuestion := q
	// Check context cancellation at the beginning of the loop
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	finalMsg := new(dns.Msg)
	finalMsg.SetQuestion(originalQuestion.Name, originalQuestion.Qtype)

	// currentZone tracks the zone for which we currently have authoritative servers.
	// It starts at the root.
	currentZone := "."

	for i := 0; i < 20; i++ { // Limit iterations to prevent infinite loops
		// Always query for the original question name.
		// The delegation logic will ensure we query the correct authoritative servers.
		queryName := originalQuestion.Name

		log.Printf("Querying servers for %s (currentZone: %s): %v", queryName, currentZone, servers)

		// Create a new question with the full name
		resp, server, err := queryServers(ctx, dns.Question{Name: queryName, Qtype: q.Qtype, Qclass: q.Qclass}, servers, doBit)
		if err != nil {
			log.Printf("Error querying %s from %s: %v", queryName, server, err)
			return nil, err
		}

		if resp.Rcode != dns.RcodeSuccess {
			log.Printf("Query for %s failed with rcode %s from %s. Response: %s", queryName, dns.RcodeToString[resp.Rcode], server, resp.String())
			// If the response is a server failure from an upstream, propagate it.
			if resp.Rcode == dns.RcodeServerFailure {
				return resp, fmt.Errorf("upstream server %s returned SERVFAIL for %s", server, queryName)
			}
			if len(finalMsg.Answer) > 0 { // If we collected CNAMEs, return them with the error code
				finalMsg.Rcode = resp.Rcode
				finalMsg.Ns = resp.Ns
				return finalMsg, nil
			}
			return resp, nil // Return the error response directly
		}

		// Check if we got the answer for the original question
		if len(resp.Answer) > 0 {
			foundAnswerForOriginal := false
			foundCNAME := false
			for _, rr := range resp.Answer {
				if rr.Header().Name == originalQuestion.Name && rr.Header().Rrtype == originalQuestion.Qtype {
					finalMsg.Answer = append(finalMsg.Answer, rr)
					foundAnswerForOriginal = true
				} else if cname, ok := rr.(*dns.CNAME); ok && cname.Header().Name == originalQuestion.Name {
					finalMsg.Answer = append(finalMsg.Answer, rr)
					if originalQuestion.Qtype != dns.TypeCNAME {
						log.Printf("Following CNAME from %s to %s", originalQuestion.Name, cname.Target)
						originalQuestion.Name = cname.Target // Update original question to follow CNAME
						currentZone = "."                    // Reset current zone to roots for new target
						servers = RootServers                // Restart with new name from roots
						foundCNAME = true
						break // Break from this answer loop to restart resolution for CNAME target
					}
				} else {
					finalMsg.Answer = append(finalMsg.Answer, rr) // Add other relevant answers
				}
			}

			if foundCNAME {
				continue // Continue loop to resolve the CNAME target
			}
			if foundAnswerForOriginal {
				log.Printf("Found answer for %s. Response: %s", originalQuestion.Name, finalMsg.String())
				finalMsg.Rcode = dns.RcodeSuccess
				CacheResponse(originalQuestion, finalMsg)
				return finalMsg, nil
			}
		}

		// Extract delegation and continue recursion
		nextServers, hasGlue := extractDelegation(resp)
		if len(nextServers) > 0 { // If delegation exists, follow it
			// Update currentZone to the delegated zone
			delegatedZone := ""
			for _, rr := range resp.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					delegatedZone = ns.Header().Name
					break
				}
			}

			if delegatedZone != "" {
				currentZone = delegatedZone
			} else {
				log.Printf("Warning: No delegated zone found in NS records for %s. Keeping current zone.", queryName)
			}

			if !hasGlue {
				log.Printf("Resolving NS IPs for delegation of %s", currentZone)
				resolvedIPs, err := resolveNS(ctx, nextServers, doBit)
				if err != nil {
					log.Printf("Error resolving NS IPs for %s: %v", currentZone, err)
					return nil, err
				}
				servers = resolvedIPs
			} else {
				servers = nextServers
			}
			continue // Continue loop with new servers
		}

		// Handle negative caching (NXDOMAIN/NODATA) only if no answer and no delegation was found
		if resp.Rcode == dns.RcodeNameError || (resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 && len(resp.Ns) > 0) {
			var soaMinTTL uint32 = 0
			for _, rr := range resp.Ns {
				if soa, ok := rr.(*dns.SOA); ok {
					soaMinTTL = soa.Minttl
					break
				}
			}
			if soaMinTTL > 0 {
				CacheNegativeResponse(originalQuestion, resp, soaMinTTL)
				log.Printf("Cached negative response for %s with SOA MINIMUM TTL %d", originalQuestion.Name, soaMinTTL)
			} else {
				CacheNegativeResponse(originalQuestion, resp, 600) // Default to 10 minutes
				log.Printf("Cached negative response for %s with default TTL (no SOA MINIMUM)", originalQuestion.Name)
			}
			return resp, nil // Return the negative response
		}

		// If no answer, no CNAME, no delegation, and not a negative response, then we've hit a dead end.
		log.Printf("No answer, CNAME, delegation, or negative response found for %s. Response: %s", queryName, resp.String())
		if len(finalMsg.Answer) > 0 { // If we collected CNAMEs, return them
			finalMsg.Rcode = resp.Rcode
			finalMsg.Ns = resp.Ns
			return finalMsg, nil
		}
		return resp, nil // No progress, return current response
	}
	return nil, fmt.Errorf("resolution depth limit exceeded for %s", originalQuestion.Name)
}

func queryServers(ctx context.Context, q dns.Question, servers []string, doBit bool) (*dns.Msg, string, error) {
	// Use the provided context for the overall query operation.
	// The individual client timeout is still applied for each exchange.
	clientTimeout := 5 * time.Second

	respChan := make(chan struct {
		Msg    *dns.Msg
		Server string
	}, 1)

	// Shuffle servers to distribute load and try different ones
	shuffledServers := make([]string, len(servers))
	perm := rand.Perm(len(servers))
	for i, v := range perm {
		shuffledServers[i] = servers[v]
	}

	// Limit concurrent queries to a smaller number (e.g., 5)
	maxConcurrentQueries := 5
	if len(shuffledServers) < maxConcurrentQueries {
		maxConcurrentQueries = len(shuffledServers)
	}

	var wg sync.WaitGroup
	for i := 0; i < maxConcurrentQueries; i++ {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			c := new(dns.Client)
			c.Timeout = clientTimeout // Set timeout for the client
			m := new(dns.Msg)
			m.SetQuestion(q.Name, q.Qtype)
			m.RecursionDesired = false
			m.SetEdns0(1232, doBit) // EDNS payload limited to 1232 bytes

			resp, _, err := c.ExchangeContext(ctx, m, s)

			if err == nil && resp != nil {
				if resp.Truncated {
					log.Printf("Response for %s from %s was truncated. Retrying over TCP.", q.Name, s)
					// Retry over TCP
					tcpClient := new(dns.Client)
					tcpClient.Net = "tcp"
					tcpClient.Timeout = c.Timeout // Use the same timeout as UDP
					tcpResp, _, tcpErr := tcpClient.ExchangeContext(ctx, m, s)
					if tcpErr == nil && tcpResp != nil {
						resp = tcpResp // Use the TCP response
					} else {
						log.Printf("TCP retry for %s from %s failed: %v", q.Name, s, tcpErr)
					}
				}

				// Only consider successful responses or specific error codes that indicate a definitive answer (e.g., NXDOMAIN)
				// Do not send SERVFAIL from upstream to the channel, as we want to retry other servers.
				if resp.Rcode != dns.RcodeServerFailure {
					select {
					case respChan <- struct {
						Msg    *dns.Msg
						Server string
					}{resp, s}:
					default: // Avoid blocking if another goroutine already sent a response
					}
				} else {
					log.Printf("Upstream server %s returned SERVFAIL for %s. Will try other servers.", s, q.Name)
				}
			} else if err != nil {
				log.Printf("Error exchanging DNS query for %s with %s: %v", q.Name, s, err)
			}
		}(shuffledServers[i])
	}

	go func() {
		wg.Wait()
		close(respChan)
	}()

	select {
	case res, ok := <-respChan:
		if !ok {
			// This happens if all goroutines failed without sending a response.
			return nil, "", fmt.Errorf("all queries failed for %s", q.Name)
		}
		return res.Msg, res.Server, nil
	case <-ctx.Done():
		return nil, "", fmt.Errorf("querying servers for %s timed out: %w", q.Name, ctx.Err())
	}
}

func extractCNAME(resp *dns.Msg) string {
	for _, ans := range resp.Answer {
		if c, ok := ans.(*dns.CNAME); ok {
			return c.Target
		}
	}
	return ""
}

func extractDelegation(resp *dns.Msg) (servers []string, hasGlue bool) {
	nsMap := make(map[string]bool)
	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsMap[ns.Ns] = true
		}
	}

	for _, extra := range resp.Extra {
		if a, ok := extra.(*dns.A); ok {
			if nsMap[a.Hdr.Name] {
				servers = append(servers, net.JoinHostPort(a.A.String(), "53"))
				hasGlue = true
			}
		} else if aaaa, ok := extra.(*dns.AAAA); ok {
			if nsMap[aaaa.Hdr.Name] {
				servers = append(servers, net.JoinHostPort(aaaa.AAAA.String(), "53"))
				hasGlue = true
			}
		}
	}

	if !hasGlue {
		for ns := range nsMap {
			servers = append(servers, ns)
		}
	}
	return
}

func resolveNS(ctx context.Context, nsNames []string, doBit bool) ([]string, error) {
	var ips []string
	for _, name := range nsNames {
		select {
		case <-ctx.Done():
			return nil, ctx.Err() // Propagate context cancellation
		default:
		}

		// Recursively resolve A records for the NS name
		aResp, err := ResolveDNS(ctx, dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}, doBit)
		if err == nil && aResp != nil && aResp.Rcode == dns.RcodeSuccess {
			for _, rr := range aResp.Answer {
				if a, ok := rr.(*dns.A); ok {
					ips = append(ips, net.JoinHostPort(a.A.String(), "53"))
				}
			}
		} else {
			log.Printf("Could not resolve A record for NS %s: %v", name, err)
		}

		// Recursively resolve AAAA records for the NS name if no A records were found or for more options
		if len(ips) == 0 { // Only try AAAA if A records weren't found
			aaaaResp, err := ResolveDNS(ctx, dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}, doBit)
			if err == nil && aaaaResp != nil && aaaaResp.Rcode == dns.RcodeSuccess {
				for _, rr := range aaaaResp.Answer {
					if aaaa, ok := rr.(*dns.AAAA); ok {
						ips = append(ips, net.JoinHostPort(aaaa.AAAA.String(), "53"))
					}
				}
			} else {
				log.Printf("Could not resolve AAAA record for NS %s: %v", name, err)
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("could not resolve any NS IPs for %v", nsNames)
	}
	return ips, nil
}

func CacheResponse(q dns.Question, resp *dns.Msg) {
	minTTL := uint32(3600)
	if len(resp.Answer) > 0 {
		minTTL = resp.Answer[0].Header().Ttl
		for _, ans := range resp.Answer {
			if ans.Header().Ttl < minTTL {
				minTTL = ans.Header().Ttl
			}
		}
	}

	CacheMutex.Lock()
	defer CacheMutex.Unlock()

	normalizedQName := dns.Fqdn(strings.ToLower(q.Name))
	Cache.Add(normalizedQName, CacheEntry{
		Msg:        resp,
		Expiration: time.Now().Add(time.Duration(minTTL) * time.Second),
	})
	log.Printf("Cached %s for %d seconds", q.Name, minTTL)
}

// CacheNegativeResponse caches NXDOMAIN/NODATA responses based on SOA MINIMUM TTL
func CacheNegativeResponse(q dns.Question, resp *dns.Msg, ttl uint32) {
	CacheMutex.Lock() // Use CacheMutex for NegativeCache as well
	defer CacheMutex.Unlock()

	normalizedQName := dns.Fqdn(strings.ToLower(q.Name))
	NegativeCache.Add(normalizedQName, NegativeCacheEntry{
		Msg:        resp,
		Expiration: time.Now().Add(time.Duration(ttl) * time.Second),
	})
	log.Printf("Cached negative response for %s for %d seconds", q.Name, ttl)
}

func HandleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true // Enable compression

	// Defer a panic handler. This will catch any panics in the resolution
	// process and send a SERVFAIL response.
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Recovered from panic: %v", rec)
			m.SetRcode(r, dns.RcodeServerFailure)
			// Clear any potentially incomplete data before responding
			m.Answer = []dns.RR{}
			m.Ns = []dns.RR{}
			m.Extra = []dns.RR{}
			w.WriteMsg(m)
		}
	}()

	doBit := false
	// Handle EDNS(0) for large responses
	if opt := r.IsEdns0(); opt != nil {
		doBit = opt.Do()
		// Client supports EDNS(0), use its requested UDP payload size, capped at 4096.
		udpsize := opt.UDPSize()
		if udpsize < 512 { // Minimum recommended EDNS0 size
			udpsize = 512
		}
		if udpsize > 4096 { // Cap at a reasonable maximum
			udpsize = 4096
		}
		m.SetEdns0(udpsize, doBit) // Set EDNS0 on the response with client's size and DO bit
	} else {
		// Client does not support EDNS(0) in the query, but we still advertise our capability
		// to send larger responses by including an OPT record with a default size.
		m.SetEdns0(4096, false) // Default EDNS0 size for responses
	}

	if r.Opcode == dns.OpcodeQuery {
		clientIP, _, err := net.SplitHostPort(w.RemoteAddr().String())
		if err != nil {
			log.Printf("Error getting client IP for rate limiting: %v", err)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}

		rateLimitMutex.Lock()
		// Clean up old entries
		for ip := range clientQueryTimestamps {
			if time.Since(clientQueryTimestamps[ip]) > rateLimitWindow {
				delete(clientQueryCounts, ip)
				delete(clientQueryTimestamps, ip)
			}
		}

		// Check rate limit
		if clientQueryCounts[clientIP] >= maxQueriesPerWindow {
			rateLimitMutex.Unlock()
			log.Printf("Rate limit exceeded for client IP %s", clientIP)
			m.SetRcode(r, dns.RcodeServerFailure) // Or dns.RcodeRefused
			w.WriteMsg(m)
			return
		}

		// Increment query count and update timestamp
		clientQueryCounts[clientIP]++
		clientQueryTimestamps[clientIP] = time.Now()
		rateLimitMutex.Unlock()

		for _, q := range m.Question {
			log.Printf("Received query for %s from %s", q.Name, clientIP)

			// Create a context with a timeout for the entire resolution process
			resolveCtx, cancel := context.WithTimeout(context.Background(), globalResolutionTimeout)
			defer cancel() // Ensure the context is cancelled when ResolveDNS returns

			resp, err := ResolveDNS(resolveCtx, q, doBit)
			if err != nil {
				log.Printf("Error resolving %s: %v. Setting RcodeServerFailure.", q.Name, err)
				m.SetRcode(r, dns.RcodeServerFailure)
				// Optionally, you could try to be more specific here if the error type allows.
				// For now, sticking to SERVFAIL as it's a general server-side issue.
			} else if resp != nil {
				// Copy the response fields to the message 'm'
				m.Answer = resp.Answer
				m.Ns = resp.Ns
				m.Extra = resp.Extra
				m.Rcode = resp.Rcode
			}
		}
	}
	w.WriteMsg(m)
}

func main() {
	log.SetOutput(os.Stderr)

	// Initialize LRU caches
	var err error
	Cache, err = lru.New[string, CacheEntry](maxCacheSize)
	if err != nil {
		log.Fatalf("Failed to create positive cache: %v", err)
	}
	NegativeCache, err = lru.New[string, NegativeCacheEntry](maxCacheSize)
	if err != nil {
		log.Fatalf("Failed to create negative cache: %v", err)
	}

	dns.HandleFunc(".", HandleDnsRequest)

	port := os.Getenv("DNS_PORT")
	if port == "" {
		port = "8054" // Changed default port to 8054 to avoid conflicts
	}

	go func() {
		udpServer := &dns.Server{Addr: "[::]:" + port, Net: "udp"}
		log.Printf("Starting UDP server on [::]:%s (IPv4 and IPv6)", port)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP server: %s", err)
		}
	}()

	tcpServer := &dns.Server{Addr: "[::]:" + port, Net: "tcp"}
	log.Printf("Starting TCP server on [::]:%s (IPv4 and IPv6)", port)
	if err := tcpServer.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start TCP server: %s", err)
	}
}
