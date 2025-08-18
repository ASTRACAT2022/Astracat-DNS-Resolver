package main

import (
	"log"
	"net"
	"os" // Add os for environment variable access
	"sync" // Add sync for mutex

	"github.com/miekg/dns"
)

var (
	// Simple in-memory cache for DNS responses
	cache = make(map[dns.Question]*dns.Msg)
	// Mutex to protect cache access
	cacheMutex sync.RWMutex
)

// rootServers defines the list of root DNS servers
var rootServers = []string{
	"198.41.0.4:53",    // A.ROOT-SERVERS.NET
	"199.9.14.201:53",  // B.ROOT-SERVERS.NET
	"192.33.4.12:53",   // C.ROOT-SERVERS.NET
	"199.7.91.13:53",   // D.ROOT-SERVERS.NET
	"192.203.230.10:53", // E.ROOT-SERVERS.NET
	"192.5.5.241:53",   // F.ROOT-SERVERS.NET
	"192.112.36.4:53",  // G.ROOT-SERVERS.NET
	"198.97.190.53:53", // H.ROOT-SERVERS.NET
	"192.36.148.17:53", // I.ROOT-SERVERS.NET
	"192.58.128.30:53", // J.ROOT-SERVERS.NET
	"193.0.14.129:53",  // K.ROOT-SERVERS.NET
	"199.7.83.42:53",   // L.ROOT-SERVERS.NET
	"202.12.27.33:53",  // M.ROOT-SERVERS.NET
}

// resolveDNS recursively resolves a DNS query
func resolveDNS(q dns.Question) (*dns.Msg, error) {
	log.Printf("Attempting to resolve %s (type %s)", q.Name, dns.Type(q.Qtype).String())

	// Check cache first
	cacheMutex.RLock()
	if resp, ok := cache[q]; ok {
		cacheMutex.RUnlock()
		log.Printf("Cache hit for %s", q.Name)
		return resp, nil
	}
	cacheMutex.RUnlock()

	// Start with root servers
	currentServers := rootServers
	var response *dns.Msg
	originalQuestion := q // Store the original question for caching

	for len(currentServers) > 0 {
		var nextServers []string
		resolvedCurrentQuery := false

		for _, nsAddr := range currentServers {
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion(q.Name, q.Qtype)
			m.RecursionDesired = false // Important: iterative queries to authoritative servers
			// Enable EDNS0 for larger UDP responses
			m.SetEdns0(4096, false)

			log.Printf("Querying %s for %s", nsAddr, q.Name)
			resp, _, err := c.Exchange(m, nsAddr)
			if err != nil {
				log.Printf("Error querying %s: %v", nsAddr, err)
				continue
			}

			// If we get an answer for the original query type, we are done with this iteration
			if resp != nil && len(resp.Answer) > 0 {
				// Check if any answer matches the original query type (unless it's a CNAME)
				gotFinalAnswer := false
				for _, ans := range resp.Answer {
					if ans.Header().Rrtype == q.Qtype || ans.Header().Rrtype == dns.TypeCNAME {
						gotFinalAnswer = true
						break
					}
				}
				
				if gotFinalAnswer {
					response = resp
					// Handle CNAMEs if present in answers
					for _, ans := range resp.Answer {
						if cname, ok := ans.(*dns.CNAME); ok {
							q.Name = cname.Target // Update query name to follow CNAME
							log.Printf("Following CNAME to %s", q.Name)
							// Reset current servers to root for CNAME target resolution
							currentServers = rootServers // Restart resolution for CNAME target
							resolvedCurrentQuery = true
							break
						}
					}

					// If no CNAME to follow, and we have an answer, we are done
					if !resolvedCurrentQuery {
						cacheMutex.Lock()
						cache[originalQuestion] = resp
						cacheMutex.Unlock()
						return resp, nil
					}
					break // Break inner loop if we found an answer or CNAME
				}
			}

			// If no answers, but NS records (delegation), update nextServers
			var foundNextNS bool
			for _, rr := range resp.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					// Attempt to resolve NS IP address using external resolver if needed
					// For simplicity, we assume the additional section might have A records
					// or we'd resolve it recursively (but carefully, to avoid loops)
					nsIP := "" // Placeholder for NS IP
					for _, extra := range resp.Extra {
						if a, ok := extra.(*dns.A); ok && a.Hdr.Name == ns.Ns {
							nsIP = a.A.String()
							break
						}
					}
					if nsIP == "" {
						// If A record not in additional section, try resolving NS IP using a public resolver
						log.Printf("Resolving NS IP for %s using public resolver", ns.Ns)
						publicClient := new(dns.Client)
						publicMsg := new(dns.Msg)
						publicMsg.SetQuestion(ns.Ns, dns.TypeA)
						publicMsg.RecursionDesired = true // We want recursion for this external query
						// Enable EDNS0 for public resolver queries
						publicMsg.SetEdns0(4096, false)
						
						publicResp, _, publicErr := publicClient.Exchange(publicMsg, "8.8.8.8:53") // Use Google Public DNS
						if publicErr == nil && publicResp != nil && len(publicResp.Answer) > 0 {
							for _, ans := range publicResp.Answer {
								if a, ok := ans.(*dns.A); ok {
									nsIP = a.A.String()
									break
								}
							}
						} else {
							log.Printf("Failed to resolve NS IP %s using public resolver: %v", ns.Ns, publicErr)
						}
					}
					
					if nsIP != "" {
						nextServers = append(nextServers, net.JoinHostPort(nsIP, "53"))
						foundNextNS = true
					} else {
						log.Printf("Could not resolve IP for NS: %s", ns.Ns)
					}
				}
			}
			
			// If we found next NS servers, break to start a new iteration with them
			if foundNextNS {
				currentServers = nextServers
				resolvedCurrentQuery = true
				break
			}

			// If no resolution or delegation found in this entire iteration, break outer loop
		}
		
		// If no resolution or delegation found in this entire iteration, break outer loop
		if !resolvedCurrentQuery {
			break
		}
	}
	return response, nil
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			m := new(dns.Msg)
			m.SetRcode(m, dns.RcodeServerFailure)
			w.WriteMsg(m)
		}
	}()

	// handleDnsRequest is automatically handled in a goroutine by dns.Server,
	// making it concurrent. Cache access is protected by cacheMutex.
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	// Enable EDNS0 for larger UDP responses
	m.SetEdns0(4096, false)

	if r.Opcode == dns.OpcodeQuery {
		for _, q := range m.Question {
			log.Printf("Received query for %s (type %s)", q.Name, dns.Type(q.Qtype).String())

			resp, err := resolveDNS(q)
			if err != nil {
				log.Printf("Error resolving DNS for %s: %v", q.Name, err)
				m.SetRcode(r, dns.RcodeServerFailure)
			} else if resp != nil {
				m.Answer = resp.Answer
				m.Ns = resp.Ns
				m.Extra = resp.Extra
			}
		}
	}

	w.WriteMsg(m)
}

func main() {
	// attach request handler
	dns.HandleFunc(".", handleDnsRequest)

	port := os.Getenv("DNS_PORT")
	if port == "" {
		port = "53" // Default DNS port
	}

	// start UDP server
	udpServer := &dns.Server{Addr: ":" + port, Net: "udp"}
	log.Printf("Starting UDP server on :%s", port)
	go func() {
		err := udpServer.ListenAndServe()
		defer udpServer.Shutdown()
		if err != nil {
			log.Fatalf("Failed to start UDP server: %s", err.Error())
		}
	}()

	// start TCP server
	tcpServer := &dns.Server{Addr: ":" + port, Net: "tcp"}
	log.Printf("Starting TCP server on :%s", port)
	err := tcpServer.ListenAndServe()
	defer tcpServer.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start TCP server: %s", err.Error())
	}
}
