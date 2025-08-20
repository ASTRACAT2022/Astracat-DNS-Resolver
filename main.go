package main

import (
	"context"
	"fmt"
	"io" // Replaced ioutil with io
	"log"
	rand "math/rand/v2"
	"net"
	"net/http" // Required for http.Get
	"os"
	"strings" // Added for strings.Join
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
	"198.41.0.4:53",     // A.ROOT-SERVERS.NET
	"192.228.79.201:53", // B.ROOT-SERVERS.NET (updated from 170.247.170.2)
	"192.33.4.12:53",    // C.ROOT-SERVERS.NET
	"199.7.91.13:53",    // D.ROOT-SERVERS.NET
	"192.203.230.10:53", // E.ROOT-SERVERS.NET
}

func ResolveDNS(q dns.Question, doBit bool) (*dns.Msg, error) {
	log.Printf("Resolving %s", q.Name)

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
		resp, err = ResolveRecursive(q, doBit)
		if err == nil {
			return resp, nil
		}
		log.Printf("Recursive resolution for %s failed (attempt %d/%d): %v. Retrying...", q.Name, i+1, maxRetries, err)
		time.Sleep(initialTimeout * time.Duration(1<<i)) // Exponential backoff
	}

	return nil, fmt.Errorf("failed to resolve %s after %d retries: %v", q.Name, maxRetries, err)
}

func ResolveRecursive(q dns.Question, doBit bool) (*dns.Msg, error) {
	servers := RootServers
	originalQuestion := q
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
		resp, server, err := queryServers(dns.Question{Name: queryName, Qtype: q.Qtype, Qclass: q.Qclass}, servers, doBit)
		if err != nil {
			log.Printf("Error querying %s from %s: %v", queryName, server, err)
			return nil, err
		}

		if resp.Rcode != dns.RcodeSuccess {
			log.Printf("Query for %s failed with rcode %s from %s. Response: %s", queryName, dns.RcodeToString[resp.Rcode], server, resp.String())
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
				resolvedIPs, err := resolveNS(nextServers, doBit)
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

func queryServers(q dns.Question, servers []string, doBit bool) (*dns.Msg, string, error) {
	// Set client timeout to 2-3 seconds
	clientTimeout := 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()

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

				if resp.Rcode != dns.RcodeServerFailure {
					select {
					case respChan <- struct {
						Msg    *dns.Msg
						Server string
					}{resp, s}:
					default: // Avoid blocking if another goroutine already sent a response
					}
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
		cancel() // Cancel other ongoing requests
		return res.Msg, res.Server, nil
	case <-ctx.Done():
		return nil, "", fmt.Errorf("querying servers for %s timed out", q.Name)
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

func resolveNS(nsNames []string, doBit bool) ([]string, error) {
	var ips []string
	for _, name := range nsNames {
		// Recursively resolve A records for the NS name
		aResp, err := ResolveDNS(dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}, doBit)
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
			aaaaResp, err := ResolveDNS(dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}, doBit)
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

// updateRootServers fetches the latest root server list from internic.net
// and updates the global RootServers slice.
func updateRootServers() {
	log.Println("Updating root servers from https://www.internic.net/domain/named.root")
	resp, err := http.Get("https://www.internic.net/domain/named.root")
	if err != nil {
		log.Printf("Error fetching named.root: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body) // Changed ioutil.ReadAll to io.ReadAll
	if err != nil {
		log.Printf("Error reading named.root response body: %v", err)
		return
	}

	var newRootServers []string
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ";") || line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 4 {
			if parts[2] == "A" { // Only include IPv4 addresses
				ip := parts[3]
				if !strings.Contains(ip, ":") { // Ensure it's not an IPv6 address
					newRootServers = append(newRootServers, net.JoinHostPort(ip, "53"))
				}
			}
		}
	}

	if len(newRootServers) > 0 {
		RootServers = newRootServers
		log.Printf("Successfully updated root servers. New count: %d", len(RootServers))
	} else {
		log.Println("No root servers found in the fetched file. Keeping existing list.")
	}
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
			resp, err := ResolveDNS(q, doBit)
			if err != nil {
				log.Printf("Error resolving %s: %v", q.Name, err)
				m.SetRcode(r, dns.RcodeServerFailure)
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
		port = "8053" // Changed default port to 8053 to avoid conflicts
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
