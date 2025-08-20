package main

import (
	"context"
	"fmt"
	"log"
	rand "math/rand/v2"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const maxCacheSize = 10000
const maxRetries = 3
const initialTimeout = 2 * time.Second

var (
	Cache      = make(map[dns.Question]CacheEntry)
	CacheMutex sync.RWMutex
	CacheOrder []dns.Question

	NsecCache      = make(map[string]NsecCacheEntry) // Key: NSEC owner name
	NsecCacheMutex sync.RWMutex
)

type CacheEntry struct {
	Msg        *dns.Msg
	Expiration time.Time
}

type NsecCacheEntry struct {
	NSEC       *dns.NSEC
	Expiration time.Time
}

var RootServers = []string{
	"198.41.0.4:53",            // A
	"170.247.170.2:53",         // B (обнови!)
	"192.33.4.12:53",           // C
	"199.7.91.13:53",           // D
	"192.203.230.10:53",        // E
	"192.5.5.241:53",           // F
	"192.112.36.4:53",          // G
	"198.97.190.53:53",         // H
	"192.36.148.17:53",         // I
	"192.58.128.30:53",         // J
	"193.0.14.129:53",          // K
	"199.7.83.42:53",           // L
	"202.12.27.33:53",          // M
	"[2001:503:ba3e::2:30]:53", // A IPv6
	"[2801:1b8:10::b]:53",      // B IPv6 (обнови!)
	"[2001:500:2::c]:53",       // C
	"[2001:500:2d::d]:53",      // D
	"[2001:500:a8::e]:53",      // E
	"[2001:500:2f::f]:53",      // F
	"[2001:500:12::d0d]:53",    // G
	"[2001:500:1::53]:53",      // H
	"[2001:7fe::53]:53",        // I
	"[2001:503:c27::2:30]:53",  // J
	"[2001:7fd::1]:53",         // K
	"[2001:500:9f::42]:53",     // L (исправь 3 на 9f!)
	"[2001:dc3::35]:53",        // M
}

func ResolveDNS(q dns.Question, doBit bool) (*dns.Msg, error) {
	log.Printf("Resolving %s", q.Name)

	CacheMutex.RLock()
	if entry, ok := Cache[q]; ok && time.Now().Before(entry.Expiration) {
		CacheMutex.RUnlock()
		log.Printf("Cache hit for %s", q.Name)
		return entry.Msg, nil
	}
	CacheMutex.RUnlock()

	// Check NSEC cache for negative responses
	NsecCacheMutex.RLock()
	for _, entry := range NsecCache {
		if time.Now().Before(entry.Expiration) && nsecCovers(entry.NSEC, q) {
			// This NSEC record covers the query name.

			// Case 1: The NSEC owner name is the same as the query name.
			// This means the name exists. Check for type.
			if entry.NSEC.Header().Name == q.Name {
				qtypePresentInNSEC := false
				for _, t := range entry.NSEC.TypeBitMap {
					if t == q.Qtype {
						qtypePresentInNSEC = true
						break
					}
				}
				if !qtypePresentInNSEC { // Type doesn't exist -> NODATA
					m := new(dns.Msg)
					m.SetQuestion(q.Name, q.Qtype)
					m.SetRcode(m, dns.RcodeSuccess)
					m.Ns = append(m.Ns, entry.NSEC)
					NsecCacheMutex.RUnlock()
					log.Printf("NSEC cache hit for %s: returning NODATA", q.Name)
					return m, nil
				}
				// Type exists, so we must fall through to get the record.
				log.Printf("NSEC cache hit for %s: type exists, falling through", q.Name)
				break
			} else {
				// Case 2: The NSEC owner name is different from the query name.
				// This means the query name is in the gap between owner and nextdomain,
				// which proves the query name does not exist -> NXDOMAIN.
				m := new(dns.Msg)
				m.SetQuestion(q.Name, q.Qtype)
				m.SetRcode(m, dns.RcodeNameError)
				m.Ns = append(m.Ns, entry.NSEC)
				NsecCacheMutex.RUnlock()
				log.Printf("NSEC cache hit for %s: returning NXDOMAIN", q.Name)
				return m, nil
			}
		}
	}
	NsecCacheMutex.RUnlock()

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

	for i := 0; i < 20; i++ { // Limit iterations to prevent infinite loops
		log.Printf("Querying servers for %s: %v", q.Name, servers)
		resp, server, err := queryServers(q, servers, doBit)
		if err != nil {
			log.Printf("Error querying %s from %s: %v", q.Name, server, err)
			return nil, err
		}

		if resp.Rcode != dns.RcodeSuccess {
			log.Printf("Query for %s failed with rcode %s from %s. Response: %s", q.Name, dns.RcodeToString[resp.Rcode], server, resp.String())
			// If we failed after following a CNAME, return the CNAME answer(s) we've collected
			if len(finalMsg.Answer) > 0 {
				finalMsg.Rcode = resp.Rcode
				finalMsg.Ns = resp.Ns
				return finalMsg, nil
			}
			return resp, nil
		}

		if len(resp.Answer) > 0 {
			foundCNAME := false
			for _, rr := range resp.Answer {
				finalMsg.Answer = append(finalMsg.Answer, rr)
				if cname, ok := rr.(*dns.CNAME); ok {
					// If we're specifically asking for a CNAME, don't follow it.
					if originalQuestion.Qtype != dns.TypeCNAME {
						log.Printf("Following CNAME from %s to %s", q.Name, cname.Target)
						q.Name = cname.Target
						servers = RootServers // Restart with new name from roots
						foundCNAME = true
					}
				}
			}

			if foundCNAME {
				continue // Continue loop to resolve the CNAME target
			}

			log.Printf("Found answer for %s. Response: %s", q.Name, resp.String())
			finalMsg.Rcode = dns.RcodeSuccess
			CacheResponse(originalQuestion, finalMsg)
			return finalMsg, nil
		}

		// Aggressive NSEC caching for NXDOMAIN/NODATA responses
		if resp.Rcode == dns.RcodeNameError || (resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0) {
			for _, rr := range resp.Ns {
				if nsec, ok := rr.(*dns.NSEC); ok {
					CacheNSEC(nsec)
				}
			}
		}

		nextServers, hasGlue := extractDelegation(resp)
		if len(nextServers) == 0 {
			log.Printf("No delegation found for %s. Response: %s", q.Name, resp.String())
			// If we have a CNAME, return that. Otherwise, return the empty response.
			if len(finalMsg.Answer) > 0 {
				finalMsg.Rcode = resp.Rcode
				finalMsg.Ns = resp.Ns
				return finalMsg, nil
			}
			return resp, nil // No answer, no delegation
		}

		if !hasGlue {
			log.Printf("Resolving NS IPs for delegation of %s", q.Name)
			resolvedIPs, err := resolveNS(nextServers, doBit)
			if err != nil {
				log.Printf("Error resolving NS IPs for %s: %v", q.Name, err)
				return nil, err
			}
			servers = resolvedIPs
		} else {
			servers = nextServers
		}
	}
	return nil, fmt.Errorf("resolution depth limit exceeded for %s", q.Name)
}

// nsecCovers checks if an NSEC record covers the given question's name and type.
// This is a simplified check and might need more robust implementation for full DNSSEC validation.
func nsecCovers(nsec *dns.NSEC, q dns.Question) bool {
	// Check if the NSEC record's owner name is less than or equal to the queried name
	// and the next domain name is greater than the queried name.
	// This implies the queried name is within the NSEC record's range.
	if dns.CompareDomainName(q.Name, nsec.Header().Name) >= 0 && dns.CompareDomainName(q.Name, nsec.NextDomain) < 0 {
		return true
	}
	// Handle the case where the queried name is lexicographically after the last NSEC record
	// in the zone (i.e., it wraps around to the first NSEC record).
	if dns.CompareDomainName(nsec.Header().Name, nsec.NextDomain) > 0 { // NSEC record wraps around
		if dns.CompareDomainName(q.Name, nsec.Header().Name) >= 0 || dns.CompareDomainName(q.Name, nsec.NextDomain) < 0 {
			return true
		}
	}
	return false
}

func queryServers(q dns.Question, servers []string, doBit bool) (*dns.Msg, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Increased timeout
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
			m := new(dns.Msg)
			m.SetQuestion(q.Name, q.Qtype)
			m.RecursionDesired = false
			m.SetEdns0(4096, doBit) // Propagate DO bit

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
		// For each NS name, we need to find its IP address iteratively
		// Start with root servers to resolve the NS name
		currentServersForNS := RootServers
		// Try to resolve A records first
		nsQuestionA := dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeA, Qclass: dns.ClassINET}
		// Then try to resolve AAAA records
		nsQuestionAAAA := dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}

		// Attempt to resolve A records
		for j := 0; j < 10; j++ { // Limit iterations for resolving a single NS name
			resp, _, err := queryServers(nsQuestionA, currentServersForNS, doBit)
			if err != nil {
				log.Printf("Error querying servers for NS A record %s: %v", name, err)
				break
			}

			if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
				for _, ans := range resp.Answer {
					if a, ok := ans.(*dns.A); ok {
						ips = append(ips, net.JoinHostPort(a.A.String(), "53"))
					}
				}
				if len(ips) > 0 {
					break // Found IPs for this NS name, move to next NS name in outer loop
				}
			}

			// If no answer, but there are NS records in authority section, follow them
			delegatedNS, hasGlue := extractDelegation(resp)
			if len(delegatedNS) == 0 {
				break // No further delegation for this NS name
			}

			if !hasGlue {
				var resolvedDelegatedIPs []string
				for _, nsName := range delegatedNS {
					tempServers := RootServers
					tempQ := dns.Question{Name: dns.Fqdn(nsName), Qtype: dns.TypeA, Qclass: dns.ClassINET} // Still querying for A records here
					for k := 0; k < 5; k++ {
						tempResp, _, tempErr := queryServers(tempQ, tempServers, doBit)
						if tempErr != nil {
							log.Printf("Error resolving sub-NS %s: %v", nsName, tempErr)
							break
						}
						if tempResp.Rcode == dns.RcodeSuccess && len(tempResp.Answer) > 0 {
							for _, ans := range tempResp.Answer {
								if a, ok := ans.(*dns.A); ok {
									resolvedDelegatedIPs = append(resolvedDelegatedIPs, net.JoinHostPort(a.A.String(), "53"))
								}
							}
							break
						}
						tempNextServers, tempHasGlue := extractDelegation(tempResp)
						if len(tempNextServers) == 0 {
							break
						}
						if !tempHasGlue {
							tempServers = tempNextServers
						} else {
							tempServers = tempNextServers
						}
					}
				}
				if len(resolvedDelegatedIPs) > 0 {
					currentServersForNS = resolvedDelegatedIPs
				} else {
					break
				}
			} else {
				currentServersForNS = delegatedNS
			}
		}

		// Attempt to resolve AAAA records if no A records were found or if we need more options
		if len(ips) == 0 {
			currentServersForNS = RootServers // Reset servers for AAAA lookup
			for j := 0; j < 10; j++ {
				resp, _, err := queryServers(nsQuestionAAAA, currentServersForNS, doBit)
				if err != nil {
					log.Printf("Error querying servers for NS AAAA record %s: %v", name, err)
					break
				}

				if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
					for _, ans := range resp.Answer {
						if aaaa, ok := ans.(*dns.AAAA); ok {
							ips = append(ips, net.JoinHostPort(aaaa.AAAA.String(), "53"))
						}
					}
					if len(ips) > 0 {
						break
					}
				}

				delegatedNS, hasGlue := extractDelegation(resp)
				if len(delegatedNS) == 0 {
					break
				}

				if !hasGlue {
					var resolvedDelegatedIPs []string
					for _, nsName := range delegatedNS {
						tempServers := RootServers
						tempQ := dns.Question{Name: dns.Fqdn(nsName), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET} // Query for AAAA records here
						for k := 0; k < 5; k++ {
							tempResp, _, tempErr := queryServers(tempQ, tempServers, doBit)
							if tempErr != nil {
								log.Printf("Error resolving sub-NS %s: %v", nsName, tempErr)
								break
							}
							if tempResp.Rcode == dns.RcodeSuccess && len(tempResp.Answer) > 0 {
								for _, ans := range tempResp.Answer {
									if aaaa, ok := ans.(*dns.AAAA); ok {
										resolvedDelegatedIPs = append(resolvedDelegatedIPs, net.JoinHostPort(aaaa.AAAA.String(), "53"))
									}
								}
								break
							}
							tempNextServers, tempHasGlue := extractDelegation(tempResp)
							if len(tempNextServers) == 0 {
								break
							}
							if !tempHasGlue {
								tempServers = tempNextServers
							} else {
								tempServers = tempNextServers
							}
						}
					}
					if len(resolvedDelegatedIPs) > 0 {
						currentServersForNS = resolvedDelegatedIPs
					} else {
						break
					}
				} else {
					currentServersForNS = delegatedNS
				}
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

	if len(Cache) >= maxCacheSize {
		oldestQ := CacheOrder[0]
		delete(Cache, oldestQ)
		CacheOrder = CacheOrder[1:]
	}

	Cache[q] = CacheEntry{
		Msg:        resp,
		Expiration: time.Now().Add(time.Duration(minTTL) * time.Second),
	}
	CacheOrder = append(CacheOrder, q)
	log.Printf("Cached %s for %d seconds", q.Name, minTTL)
}

func CacheNSEC(nsec *dns.NSEC) {
	NsecCacheMutex.Lock()
	defer NsecCacheMutex.Unlock()

	// Use the NSEC record's TTL for caching
	minTTL := nsec.Header().Ttl
	if minTTL == 0 {
		minTTL = 3600 // Default TTL if not specified
	}

	NsecCache[nsec.Header().Name] = NsecCacheEntry{
		NSEC:       nsec,
		Expiration: time.Now().Add(time.Duration(minTTL) * time.Second),
	}
	log.Printf("Cached NSEC for %s for %d seconds", nsec.Header().Name, minTTL)
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
		for _, q := range m.Question {
			log.Printf("Received query for %s", q.Name)
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
	dns.HandleFunc(".", HandleDnsRequest)

	port := os.Getenv("DNS_PORT")
	if port == "" {
		port = "53"
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
