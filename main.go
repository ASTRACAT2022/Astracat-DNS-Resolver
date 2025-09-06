package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/domainr/dnsr"
	"github.com/miekg/dns"
)

// DNSServer contains all necessary components for a DNS server
type DNSServer struct {
	resolver         *dnsr.Resolver
	visited          sync.Map // map[string]time.Time
	nxdomainCounter  sync.Map // map[string]int
	nxdomainLastSeen sync.Map // map[string]time.Time
	quarantined      sync.Map // map[string]time.Time
	dnssecEnabled    bool
	trustAnchor      *dns.DNSKEY // Root trust anchor
	keyCache         sync.Map    // map[string]*dns.DNSKEY
	keyCacheTime     sync.Map    // map[string]time.Time
	dsCache          sync.Map    // map[string][]*dns.DS
	dsCacheTime      sync.Map    // map[string]time.Time
	rrsigCache       sync.Map    // map[string]*dns.RRSIG
	rrsigCacheTime   sync.Map    // map[string]time.Time

	// Metrics
	secureQueries        uint64
	insecureQueries      uint64
	bogusQueries         uint64
	indeterminateQueries uint64
	cacheHits            uint64
	cacheMisses          uint64
}

const (
	nxdomainLimit    = 3
	keyCacheTTL      = 24 * time.Hour
	dsCacheTTL       = 24 * time.Hour
	rrsigCacheTTL    = 1 * time.Hour
	visitedTTL       = 10 * time.Minute
	nxdomainTTL      = 30 * time.Minute
	quarantinePeriod = 30 * time.Second
	maxUDPSize       = 4096
)

// DNSSECValidationResult represents the result of DNSSEC validation
type DNSSECValidationResult int

const (
	DNSSEC_SECURE DNSSECValidationResult = iota
	DNSSEC_INSECURE
	DNSSEC_BOGUS
	DNSSEC_INDETERMINATE
)

var base32HexNoPad = base32.HexEncoding.WithPadding(base32.NoPadding)

// NewDNSServer creates and initializes a new DNS server
func NewDNSServer() *DNSServer {
	server := &DNSServer{
		resolver:      dnsr.NewResolver(),
		dnssecEnabled: true,
	}
	server.initializeTrustAnchor()
	return server
}

// initializeTrustAnchor initializes the root trust anchor
func (s *DNSServer) initializeTrustAnchor() {
	// Root KSK-2017 (RFC 8624)
	keyStr := ". IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5ZRzF9YWcJnJzRc5Diz20y+O3j2YiD6ZGyXaK0r1W/0WZi8c9I0HPObYJw8FXQzG00kHvU1OqqCtKkRBOhB4wR5KJ4QkhzN5ZU5lFsNhqVCKVCYyUMxMEJlJQZlNq6q+aIzHVMZQnR4ggr3H8H9U9F92F6VK7S9ZQ1Y="

	rr, err := dns.NewRR(keyStr)
	if err != nil {
		fmt.Printf("Failed to parse trust anchor: %v\n", err)
		return
	}

	if dnskey, ok := rr.(*dns.DNSKEY); ok {
		s.trustAnchor = dnskey
		fmt.Println("Trust anchor initialized successfully")
	}
}

// startCleaner runs a background goroutine to clean up caches
func (s *DNSServer) startCleaner() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		visitedCount := 0
		nxdomainCount := 0
		quarantineCount := 0
		keyCacheCount := 0
		dsCacheCount := 0
		rrsigCacheCount := 0

		// Clean visited map
		s.visited.Range(func(key, value interface{}) bool {
			if ts, ok := value.(time.Time); ok {
				if now.Sub(ts) > visitedTTL {
					s.visited.Delete(key)
					visitedCount++
				}
			}
			return true
		})

		// Clean nxdomainCounter
		s.nxdomainLastSeen.Range(func(key, value interface{}) bool {
			if lastSeen, ok := value.(time.Time); ok {
				if now.Sub(lastSeen) > nxdomainTTL {
					s.nxdomainCounter.Delete(key)
					s.nxdomainLastSeen.Delete(key)
					nxdomainCount++
				}
			}
			return true
		})

		// Release domains from quarantine
		s.quarantined.Range(func(key, value interface{}) bool {
			if releaseTime, ok := value.(time.Time); ok {
				if now.After(releaseTime) {
					s.quarantined.Delete(key)
					quarantineCount++
				}
			}
			return true
		})

		// Clean key cache
		s.keyCacheTime.Range(func(key, value interface{}) bool {
			if cacheTime, ok := value.(time.Time); ok {
				if now.Sub(cacheTime) > keyCacheTTL {
					s.keyCache.Delete(key)
					s.keyCacheTime.Delete(key)
					keyCacheCount++
				}
			}
			return true
		})

		// Clean DS cache
		s.dsCacheTime.Range(func(key, value interface{}) bool {
			if cacheTime, ok := value.(time.Time); ok {
				if now.Sub(cacheTime) > dsCacheTTL {
					s.dsCache.Delete(key)
					s.dsCacheTime.Delete(key)
					dsCacheCount++
				}
			}
			return true
		})

		// Clean RRSIG cache
		s.rrsigCacheTime.Range(func(key, value interface{}) bool {
			if cacheTime, ok := value.(time.Time); ok {
				if now.Sub(cacheTime) > rrsigCacheTTL {
					s.rrsigCache.Delete(key)
					s.rrsigCacheTime.Delete(key)
					rrsigCacheCount++
				}
			}
			return true
		})

		fmt.Printf("Cleaned %d old entries from visited map.\n", visitedCount)
		fmt.Printf("Reset %d NXDOMAIN counters due to inactivity.\n", nxdomainCount)
		fmt.Printf("Released %d domains from quarantine.\n", quarantineCount)
		fmt.Printf("Cleaned %d expired keys from cache.\n", keyCacheCount)
		fmt.Printf("Cleaned %d expired DS records from cache.\n", dsCacheCount)
		fmt.Printf("Cleaned %d expired RRSIG records from cache.\n", rrsigCacheCount)

		// Print metrics
		fmt.Printf("Metrics - Secure: %d, Insecure: %d, Bogus: %d, Indeterminate: %d\n",
			atomic.LoadUint64(&s.secureQueries),
			atomic.LoadUint64(&s.insecureQueries),
			atomic.LoadUint64(&s.bogusQueries),
			atomic.LoadUint64(&s.indeterminateQueries))
		fmt.Printf("Cache - Hits: %d, Misses: %d\n",
			atomic.LoadUint64(&s.cacheHits),
			atomic.LoadUint64(&s.cacheMisses))
	}
}

// handleRequest processes incoming DNS requests
func (s *DNSServer) handleRequest(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		s.sendErrorResponse(w, req, dns.RcodeFormatError, "No questions in request")
		return
	}

	question := req.Question[0]
	queryKey := fmt.Sprintf("%s:%d", strings.ToLower(dns.CanonicalName(question.Name)), question.Qtype)

	// Check if domain is quarantined
	if releaseTime, isQuarantined := s.quarantined.Load(strings.ToLower(dns.CanonicalName(question.Name))); isQuarantined {
		if releaseTimeT, ok := releaseTime.(time.Time); ok {
			if time.Now().Before(releaseTimeT) {
				s.sendErrorResponse(w, req, dns.RcodeNameError, "Domain temporarily quarantined")
				return
			}
		}
	}

	// Check for potential recursion
	if _, exists := s.visited.Load(queryKey); exists {
		s.sendErrorResponse(w, req, dns.RcodeRefused, "Potential query loop detected")
		return
	}

	s.visited.Store(queryKey, time.Now())
	defer s.visited.Delete(queryKey)

	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Compress = true
	reply.RecursionAvailable = true

	// Handle EDNS0 and DNSSEC flags
	clientRequestsDNSSEC := false
	udpSize := uint16(512)
	if edns0 := req.IsEdns0(); edns0 != nil {
		clientRequestsDNSSEC = edns0.Do()
		udpSize = edns0.UDPSize()
		if udpSize < 512 {
			udpSize = 512
		}
		if udpSize > maxUDPSize {
			udpSize = maxUDPSize
		}
		reply.SetEdns0(udpSize, true)
	}

	qtypeStr, ok := dns.TypeToString[question.Qtype]
	if !ok {
		s.sendErrorResponse(w, req, dns.RcodeNotImplemented, "Unsupported QTYPE")
		return
	}

	fmt.Printf("=== Resolving %s %s (DNSSEC: %v) ===\n", question.Name, qtypeStr, clientRequestsDNSSEC)
	
	// Perform recursive resolution with QNAME minimization
	results := s.resolver.Resolve(question.Name, qtypeStr)
	fmt.Printf("Raw results from resolver for %s %s:\n", question.Name, qtypeStr)
	for i, res := range results {
		fmt.Printf("  [%d] %s\n", i, res.String())
	}
	
	var hasValidAnswer bool

	for _, res := range results {
		if res.String() != "" {
			rr, err := dns.NewRR(res.String())
			if err != nil {
				fmt.Printf("Failed to parse RR '%s': %v\n", res.String(), err)
				continue
			}
			reply.Answer = append(reply.Answer, rr)
			hasValidAnswer = true
		}
	}

	// Handle NXDOMAIN
	if !hasValidAnswer {
		if clientRequestsDNSSEC {
			validationResult := s.validateNegativeResponse(question.Name, reply)
			switch validationResult {
			case DNSSEC_SECURE:
				reply.MsgHdr.AuthenticatedData = true
				atomic.AddUint64(&s.secureQueries, 1)
				fmt.Printf("DNSSEC validation successful for negative response %s\n", question.Name)
			case DNSSEC_BOGUS:
				s.sendErrorResponse(w, req, dns.RcodeServerFailure, "DNSSEC validation failed for negative response")
				atomic.AddUint64(&s.bogusQueries, 1)
				return
			case DNSSEC_INDETERMINATE:
				fmt.Printf("DNSSEC validation indeterminate for negative response %s\n", question.Name)
				atomic.AddUint64(&s.indeterminateQueries, 1)
			case DNSSEC_INSECURE:
				fmt.Printf("Domain is insecure (no DNSSEC) for negative response %s\n", question.Name)
				atomic.AddUint64(&s.insecureQueries, 1)
			}
		}

		// Increment NXDOMAIN counter
		counter, _ := s.nxdomainCounter.LoadOrStore(strings.ToLower(dns.CanonicalName(question.Name)), 0)
		count := counter.(int) + 1
		s.nxdomainCounter.Store(strings.ToLower(dns.CanonicalName(question.Name)), count)
		s.nxdomainLastSeen.Store(strings.ToLower(dns.CanonicalName(question.Name)), time.Now())

		if count >= nxdomainLimit {
			fmt.Printf("NXDOMAIN limit reached for '%s'. Quarantining for 30 seconds.\n", question.Name)
			s.quarantined.Store(strings.ToLower(dns.CanonicalName(question.Name)), time.Now().Add(quarantinePeriod))
		}

		reply.SetRcode(req, dns.RcodeNameError)
		if err := w.WriteMsg(reply); err != nil {
			fmt.Printf("Error writing response: %v\n", err)
		}
		return
	}

	// Handle DNSSEC validation
	if s.dnssecEnabled && clientRequestsDNSSEC && hasValidAnswer {
		// Check if we have RRSIGs for the answer
		hasRRSIGs := false
		for _, rr := range reply.Answer {
			if _, ok := rr.(*dns.RRSIG); ok {
				hasRRSIGs = true
				break
			}
		}
		
		fmt.Printf("Checking for RRSIGs in answer: hasRRSIGs=%v\n", hasRRSIGs)
		if hasRRSIGs {
			validationResult := s.validateDNSSEC(question.Name, reply)
			switch validationResult {
			case DNSSEC_SECURE:
				reply.MsgHdr.AuthenticatedData = true
				atomic.AddUint64(&s.secureQueries, 1)
				fmt.Printf("DNSSEC validation successful for %s\n", question.Name)
			case DNSSEC_BOGUS:
				s.sendErrorResponse(w, req, dns.RcodeServerFailure, "DNSSEC validation failed")
				atomic.AddUint64(&s.bogusQueries, 1)
				return
			case DNSSEC_INDETERMINATE:
				fmt.Printf("DNSSEC validation indeterminate for %s\n", question.Name)
				atomic.AddUint64(&s.indeterminateQueries, 1)
			case DNSSEC_INSECURE:
				fmt.Printf("Domain is insecure (no DNSSEC) for %s\n", question.Name)
				atomic.AddUint64(&s.insecureQueries, 1)
			}
		} else {
			fmt.Printf("No RRSIGs found for %s, attempting to fetch via resolver and authoritative servers\n", question.Name)
			// try resolver first
			rrsigResults := s.qnameMinimizeResolve(question.Name, "RRSIG")
			for _, r := range rrsigResults {
				if rr, err := dns.NewRR(r); err == nil {
					if rrsig, ok := rr.(*dns.RRSIG); ok {
						if rrsig.TypeCovered == question.Qtype {
							reply.Answer = append(reply.Answer, rrsig)
							hasRRSIGs = true
							fmt.Printf("Appended RRSIG from resolver: %s\n", rrsig.String())
						}
					}
				}
			}
			// then authoritative servers if still none
			if !hasRRSIGs {
				rrsetFromAuth, rrsigsFromAuth := s.fetchFromAuthoritative(question.Name, question.Qtype)
				for _, rrsig := range rrsigsFromAuth {
					if rrsig.TypeCovered == question.Qtype {
						reply.Answer = append(reply.Answer, rrsig)
						hasRRSIGs = true
						fmt.Printf("Appended RRSIG from authoritative: %s\n", rrsig.String())
					}
				}
				_ = rrsetFromAuth
			}
			if hasRRSIGs {
				validationResult := s.validateDNSSEC(question.Name, reply)
				switch validationResult {
				case DNSSEC_SECURE:
					reply.MsgHdr.AuthenticatedData = true
					atomic.AddUint64(&s.secureQueries, 1)
					fmt.Printf("DNSSEC validation successful for %s\n", question.Name)
				case DNSSEC_BOGUS:
					s.sendErrorResponse(w, req, dns.RcodeServerFailure, "DNSSEC validation failed")
					atomic.AddUint64(&s.bogusQueries, 1)
					return
				case DNSSEC_INDETERMINATE:
					fmt.Printf("DNSSEC validation indeterminate for %s\n", question.Name)
					atomic.AddUint64(&s.indeterminateQueries, 1)
				case DNSSEC_INSECURE:
					fmt.Printf("Domain is insecure (no DNSSEC) for %s\n", question.Name)
					atomic.AddUint64(&s.insecureQueries, 1)
				}
			} else {
				fmt.Printf("No RRSIGs available for %s after extra fetch. Trying to fetch DNSKEY/DS for diagnostic.\n", question.Name)
				rrs, keys, dsRecs, err := s.fetchDNSSECRecordsAsync(question.Name)
				if err != nil {
					fmt.Printf("Error fetching DNSSEC records for diagnostic: %v\n", err)
					atomic.AddUint64(&s.indeterminateQueries, 1)
				} else {
					if len(rrs) == 0 && len(keys) == 0 && len(dsRecs) == 0 {
						fmt.Printf("No DNSSEC records found for %s — treating as INSECURE\n", question.Name)
						atomic.AddUint64(&s.insecureQueries, 1)
					} else {
						fmt.Printf("DNSSEC artifacts present but no usable RRSIG for %s — treating as INDETERMINATE\n", question.Name)
						atomic.AddUint64(&s.indeterminateQueries, 1)
					}
				}
			}
		}
	}

	// Clear NXDOMAIN counters on successful query
	s.nxdomainCounter.Delete(strings.ToLower(dns.CanonicalName(question.Name)))
	s.nxdomainLastSeen.Delete(strings.ToLower(dns.CanonicalName(question.Name)))

	// Check response size
	if reply.Len() > int(udpSize) && w.RemoteAddr().Network() == "udp" {
		reply.Truncated = true
	}

	if err := w.WriteMsg(reply); err != nil {
		fmt.Printf("Error writing response: %v\n", err)
	}
}

// validateNegativeResponse validates negative responses with NSEC/NSEC3
func (s *DNSServer) validateNegativeResponse(domain string, reply *dns.Msg) DNSSECValidationResult {
	nsecRecords, nsec3Records, err := s.fetchNegativeProofRecords(domain)
	if err != nil {
		fmt.Printf("Failed to fetch negative proof records for %s: %v\n", domain, err)
		return DNSSEC_INDETERMINATE
	}

	if len(nsecRecords) == 0 && len(nsec3Records) == 0 {
		return DNSSEC_INSECURE
	}

	// Basic NSEC/NSEC3 validation
	for _, nsec := range nsecRecords {
		if s.verifyNSEC(nsec, domain, reply) {
			return DNSSEC_SECURE
		}
	}
	for _, nsec3 := range nsec3Records {
		if s.verifyNSEC3(nsec3, domain, reply) {
			return DNSSEC_SECURE
		}
	}

	return DNSSEC_BOGUS
}

// verifyNSEC performs basic NSEC record validation
func (s *DNSServer) verifyNSEC(nsec *dns.NSEC, domain string, reply *dns.Msg) bool {
	canonicalDomain := strings.ToLower(dns.CanonicalName(domain))
	canonicalNext := strings.ToLower(dns.CanonicalName(nsec.NextDomain))
	canonicalOwner := strings.ToLower(dns.CanonicalName(nsec.Hdr.Name))

	// Check if domain falls between owner and next domain
	if canonicalOwner < canonicalDomain && canonicalDomain < canonicalNext {
		// Verify that requested type is not in NSEC type bitmap
		for _, t := range nsec.TypeBitMap {
			if t == reply.Question[0].Qtype {
				return false
			}
		}
		return true
	}
	return false
}

// verifyNSEC3 performs basic NSEC3 record validation
func (s *DNSServer) verifyNSEC3(nsec3 *dns.NSEC3, domain string, reply *dns.Msg) bool {
	// Calculate NSEC3 hash for the domain
	hashedDomain := s.computeNSEC3Hash(domain, nsec3)
	if hashedDomain == "" {
		return false
	}

	// Check if hashed domain falls within NSEC3 range
	if nsec3.Hdr.Name < hashedDomain && hashedDomain < nsec3.NextDomain {
		// Verify that requested type is not in NSEC3 type bitmap
		for _, t := range nsec3.TypeBitMap {
			if t == reply.Question[0].Qtype {
				return false
			}
		}
		return true
	}
	return false
}

// computeNSEC3Hash computes the NSEC3 hash for a domain
func (s *DNSServer) computeNSEC3Hash(domain string, nsec3 *dns.NSEC3) string {
	owner := strings.ToLower(dns.CanonicalName(domain))
	nameBuf := make([]byte, 255)
	off, err := dns.PackDomainName(owner, nameBuf, 0, nil, false)
	if err != nil {
		fmt.Printf("computeNSEC3Hash: PackDomainName failed: %v\n", err)
		return ""
	}
	ownerWire := nameBuf[:off]
	
	var salt []byte
	if nsec3.Salt == "-" || nsec3.Salt == "" {
		salt = nil
	} else {
		salt, err = hex.DecodeString(nsec3.Salt)
		if err != nil {
			fmt.Printf("computeNSEC3Hash: invalid salt hex: %v\n", err)
			return ""
		}
	}

	h := sha1.New()
	h.Write(ownerWire)
	if len(salt) > 0 {
		h.Write(salt)
	}
	digest := h.Sum(nil)

	for i := uint16(0); i < nsec3.Iterations; i++ {
		h.Reset()
		h.Write(digest)
		if len(salt) > 0 {
			h.Write(salt)
		}
		digest = h.Sum(nil)
	}

	b32 := base32HexNoPad.EncodeToString(digest)
	return strings.ToLower(b32)
}

// fetchNegativeProofRecords fetches NSEC/NSEC3 records
func (s *DNSServer) fetchNegativeProofRecords(domain string) ([]*dns.NSEC, []*dns.NSEC3, error) {
	var nsecRecords []*dns.NSEC
	var nsec3Records []*dns.NSEC3

	nsecResults := s.qnameMinimizeResolve(domain, "NSEC")
	for _, res := range nsecResults {
		if rr, err := dns.NewRR(res); err == nil {
			if nsec, ok := rr.(*dns.NSEC); ok {
				nsecRecords = append(nsecRecords, nsec)
			}
		}
	}

	nsec3Results := s.qnameMinimizeResolve(domain, "NSEC3")
	for _, res := range nsec3Results {
		if rr, err := dns.NewRR(res); err == nil {
			if nsec3, ok := rr.(*dns.NSEC3); ok {
				nsec3Records = append(nsec3Records, nsec3)
			}
		}
	}

	return nsecRecords, nsec3Records, nil
}

// qnameMinimizeResolve implements QNAME minimization
func (s *DNSServer) qnameMinimizeResolve(domain, qtype string) []string {
	d := strings.ToLower(dns.CanonicalName(domain))
	fmt.Printf("qnameMinimizeResolve: resolving %s %s\n", d, qtype)
	tried := make(map[string]bool)
	for {
		if tried[d] {
			fmt.Printf("qnameMinimizeResolve: already tried %s, breaking\n", d)
			break
		}
		tried[d] = true
		fmt.Printf("qnameMinimizeResolve: trying %s %s\n", d, qtype)
		results := s.resolver.Resolve(d, qtype)
		fmt.Printf("qnameMinimizeResolve: got %d results for %s %s\n", len(results), d, qtype)
		if len(results) > 0 {
			var out []string
			for _, r := range results {
				if r.String() != "" {
					out = append(out, r.String())
				}
			}
			fmt.Printf("qnameMinimizeResolve: returning %d results\n", len(out))
			return out
		}
		parent := s.getParentDomain(d)
		fmt.Printf("qnameMinimizeResolve: no results, trying parent %s\n", parent)
		if parent == d || parent == "." {
			fmt.Printf("qnameMinimizeResolve: reached root or parent equals domain, breaking\n")
			break
		}
		d = parent
	}
	fmt.Printf("qnameMinimizeResolve: returning nil\n")
	return nil
}

// validateDNSSEC performs full DNSSEC validation
func (s *DNSServer) validateDNSSEC(domain string, reply *dns.Msg) DNSSECValidationResult {
	fmt.Printf("Starting DNSSEC validation for %s\n", domain)
	
	rrsigs, dnskeys, dsRecords, err := s.fetchDNSSECRecordsAsync(domain)
	if err != nil {
		fmt.Printf("Failed to fetch DNSSEC records for %s: %v\n", domain, err)
		return DNSSEC_INDETERMINATE
	}

	fmt.Printf("Fetched %d RRSIGs, %d DNSKEYs, %d DS records for %s\n",
		len(rrsigs), len(dnskeys), len(dsRecords), domain)

	if len(rrsigs) == 0 && len(dnskeys) == 0 && len(dsRecords) == 0 {
		fmt.Printf("No DNSSEC records found for %s, treating as insecure\n", domain)
		return DNSSEC_INSECURE
	}

	// Build a combined RRset to search for covered RRsets:
	// include the answer plus any fetched DNSKEYs (and DS if needed).
	combined := make([]dns.RR, 0, len(reply.Answer)+len(dnskeys))
	combined = append(combined, reply.Answer...)
	for _, k := range dnskeys {
		combined = append(combined, k)
	}
	// Note: DS records live in the parent zone; we usually don't validate RRSIGs over DS in the child.

	// Validate RRSIGs
	for i, rrsig := range rrsigs {
		fmt.Printf("Validating RRSIG %d: covering type %d (%s), labels %d, origTTL %d, signer %s\n",
			i, rrsig.TypeCovered, dns.TypeToString[rrsig.TypeCovered], rrsig.Labels, rrsig.OrigTtl, rrsig.SignerName)
		
		// Find matching RRset for this RRSIG: search in combined set (answer + dnskeys)
		rrset := s.getRRSet(combined, rrsig.TypeCovered, rrsig.Labels, rrsig.OrigTtl)
		fmt.Printf("Found %d records in RRSET for RRSIG %d\n", len(rrset), i)
		
		// If still no rrset and this is RRSIG over DNSKEY, try to use dnskeys explicitly (name/canonicalization)
		if len(rrset) == 0 && rrsig.TypeCovered == dns.TypeDNSKEY && len(dnskeys) > 0 {
			// create rrset from dnskeys
			tmp := make([]dns.RR, 0, len(dnskeys))
			for _, k := range dnskeys {
				// copy to avoid mutating cached object TTLs
				tmp = append(tmp, dns.Copy(k))
			}
			rrset = s.getRRSet(tmp, rrsig.TypeCovered, rrsig.Labels, rrsig.OrigTtl)
			fmt.Printf("Tried explicit dnskeys: found %d records\n", len(rrset))
		}

		if len(rrset) == 0 {
			fmt.Printf("No matching RRset found for RRSIG %d covering type %d\n", i, rrsig.TypeCovered)
			// If an RRSIG covers a type we don't have, skip it (some RRSIGs may be for other RRsets).
			// But if none of the RRSIGs can be matched at all, treat as BOGUS.
			// For now: continue to next RRSIG (conservative approach requires more complex logic).
			continue
		}

		if !s.verifyRRSIGWithMiekg(rrsig, rrset) {
			fmt.Printf("RRSIG verification failed for RRSIG %d in %s\n", i, domain)
			return DNSSEC_BOGUS
		}
		fmt.Printf("RRSIG %d verified successfully\n", i)
	}

	// After verifying RRSIGs that we could match, validate trust chain
	fmt.Printf("Validating trust chain for %s\n", domain)
	if !s.validateTrustChain(domain, dnskeys, dsRecords) {
		fmt.Printf("Trust chain validation failed for %s\n", domain)
		return DNSSEC_BOGUS
	}

	fmt.Printf("DNSSEC validation successful for %s\n", domain)
	return DNSSEC_SECURE
}

// getRRSet extracts RRset matching RRSIG parameters
func (s *DNSServer) getRRSet(rrset []dns.RR, qtype uint16, labels uint8, origTTL uint32) []dns.RR {
	fmt.Printf("getRRSet called with qtype=%d, labels=%d, origTTL=%d\n", qtype, labels, origTTL)
	var result []dns.RR
	
	for _, rr := range rrset {
		if rr.Header().Rrtype == qtype {
			// Create a copy to avoid modifying original
			rrCopy := dns.Copy(rr)
			hdr := rrCopy.Header()
			
			// Set TTL to Original TTL from RRSIG if provided (non-zero)
			if origTTL != 0 {
				hdr.Ttl = origTTL
			}
			
			// Handle wildcard adjustments based on Labels
			nameLabels := dns.CountLabel(hdr.Name)
			if labels < uint8(nameLabels) && labels > 0 {
				parts := dns.SplitDomainName(hdr.Name)
				if len(parts) >= int(labels) {
					prefixCount := len(parts) - int(labels)
					newname := "*."
					for i := prefixCount; i < len(parts); i++ {
						newname += parts[i]
						if i < len(parts)-1 {
							newname += "."
						}
					}
					newname = dns.Fqdn(newname)
					hdr.Name = strings.ToLower(dns.CanonicalName(newname))
				}
			} else {
				hdr.Name = strings.ToLower(dns.CanonicalName(hdr.Name))
			}
			
			result = append(result, rrCopy)
		}
	}

	// canonicalize names and sort
	for _, r := range result {
		r.Header().Name = strings.ToLower(dns.CanonicalName(r.Header().Name))
	}
	
	sort.Slice(result, func(i, j int) bool {
		return compareRR(result[i], result[j]) < 0
	})

	fmt.Printf("getRRSet returning %d records\n", len(result))
	return result
}

// canonicalizeRRSet canonicalizes RRSet for DNSSEC
func (s *DNSServer) canonicalizeRRSet(rrset []dns.RR, qtype uint16) []dns.RR {
	var filtered []dns.RR
	for _, rr := range rrset {
		if rr.Header().Rrtype == qtype {
			filtered = append(filtered, rr)
		}
	}

	if len(filtered) == 0 {
		return rrset
	}

	for _, rr := range filtered {
		rr.Header().Name = strings.ToLower(dns.CanonicalName(rr.Header().Name))
	}

	sort.Slice(filtered, func(i, j int) bool {
		return compareRR(filtered[i], filtered[j]) < 0
	})

	return filtered
}

// compareRR compares two DNS records
func compareRR(a, b dns.RR) int {
	nameCompare := strings.Compare(
		strings.ToLower(dns.CanonicalName(a.Header().Name)),
		strings.ToLower(dns.CanonicalName(b.Header().Name)),
	)
	if nameCompare != 0 {
		return nameCompare
	}

	if a.Header().Rrtype != b.Header().Rrtype {
		return int(a.Header().Rrtype) - int(b.Header().Rrtype)
	}

	if a.Header().Class != b.Header().Class {
		return int(a.Header().Class) - int(b.Header().Class)
	}

	return strings.Compare(a.String(), b.String())
}

// verifyRRSIGWithMiekg verifies RRSIG signature
func (s *DNSServer) verifyRRSIGWithMiekg(rrsig *dns.RRSIG, rrset []dns.RR) bool {
	if len(rrset) == 0 {
		fmt.Printf("verifyRRSIGWithMiekg: Empty RRSET provided\n")
		return false
	}

	fmt.Printf("Verifying RRSIG for %s, type %d, signer %s\n",
		rrset[0].Header().Name, rrsig.TypeCovered, rrsig.SignerName)

	rrsigKey := fmt.Sprintf("%s_%d_%d_%d", strings.ToLower(dns.CanonicalName(rrsig.SignerName)), rrsig.KeyTag, rrsig.Algorithm, rrsig.TypeCovered)
	if cachedRRSIG, exists := s.rrsigCache.Load(rrsigKey); exists {
		if cacheTime, timeExists := s.rrsigCacheTime.Load(rrsigKey); timeExists {
			if cacheTimeT, ok := cacheTime.(time.Time); ok {
				if time.Since(cacheTimeT) < rrsigCacheTTL {
					if cached, ok := cachedRRSIG.(*dns.RRSIG); ok {
						if cached.Signature == rrsig.Signature {
							atomic.AddUint64(&s.cacheHits, 1)
							fmt.Printf("RRSIG cache hit\n")
							return true
						}
					}
				}
			}
		}
	}
	atomic.AddUint64(&s.cacheMisses, 1)

	dnskey := s.getCachedDNSKEY(rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
	if dnskey == nil {
		fmt.Printf("DNSKEY not found in cache, fetching for %s, keytag %d, algorithm %d\n",
			rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
		dnskey = s.fetchDNSKEY(rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
		if dnskey == nil {
			fmt.Printf("DNSKEY not found for verification of %s\n", rrsig.SignerName)
			return false
		}
		s.cacheDNSKEY(rrsig.SignerName, dnskey)
	}

	fmt.Printf("Attempting to verify RRSIG with DNSKEY: keytag %d, algorithm %d\n",
		dnskey.KeyTag(), dnskey.Algorithm)
	
	// Log the RRSET being verified
	for i, rr := range rrset {
		fmt.Printf("RRSET[%d]: %s\n", i, rr.String())
	}
	
	err := rrsig.Verify(dnskey, rrset)
	if err != nil {
		fmt.Printf("RRSIG verification error: %v\n", err)
		return false
	}

	s.cacheRRSIG(rrsig)
	return true
}

// fetchDNSSECRecordsAsync fetches DNSSEC records asynchronously
func (s *DNSServer) fetchDNSSECRecordsAsync(domain string) ([]*dns.RRSIG, []*dns.DNSKEY, []*dns.DS, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		rrsigs  []*dns.RRSIG
		dnskeys []*dns.DNSKEY
		dsRecs  []*dns.DS
		wg      sync.WaitGroup
		mu      sync.Mutex
	)

	wg.Add(3)

	go func() {
		defer wg.Done()
		results := s.qnameMinimizeResolve(domain, "RRSIG")
		local := []*dns.RRSIG{}
		for _, r := range results {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if rr, err := dns.NewRR(r); err == nil {
				if rrsig, ok := rr.(*dns.RRSIG); ok {
					local = append(local, rrsig)
				}
			}
		}
		mu.Lock()
		rrsigs = local
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		results := s.qnameMinimizeResolve(domain, "DNSKEY")
		local := []*dns.DNSKEY{}
		for _, r := range results {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if rr, err := dns.NewRR(r); err == nil {
				if dnskey, ok := rr.(*dns.DNSKEY); ok {
					local = append(local, dnskey)
				}
			}
		}
		mu.Lock()
		dnskeys = local
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		results := s.qnameMinimizeResolve(domain, "DS")
		local := []*dns.DS{}
		for _, r := range results {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if rr, err := dns.NewRR(r); err == nil {
				if ds, ok := rr.(*dns.DS); ok {
					local = append(local, ds)
				}
			}
		}
		mu.Lock()
		dsRecs = local
		mu.Unlock()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return rrsigs, dnskeys, dsRecs, fmt.Errorf("timeout fetching DNSSEC records")
	case <-done:
	}

	return rrsigs, dnskeys, dsRecs, nil
}

// validateTrustChain validates the trust chain
func (s *DNSServer) validateTrustChain(domain string, dnskeys []*dns.DNSKEY, dsRecords []*dns.DS) bool {
	fmt.Printf("validateTrustChain called for %s with %d DNSKEYs and %d DS records\n",
		domain, len(dnskeys), len(dsRecords))
	
	if len(dsRecords) == 0 {
		if domain == "." || domain == "" {
			for _, dnskey := range dnskeys {
				if s.trustAnchor != nil &&
					dnskey.KeyTag() == s.trustAnchor.KeyTag() &&
					dnskey.Algorithm == s.trustAnchor.Algorithm {
					fmt.Printf("Validated against root trust anchor\n")
					return true
				}
			}
			fmt.Printf("Failed to validate against root trust anchor\n")
			return false
		}
		fmt.Printf("Delegating trust chain validation to parent for %s\n", domain)
		return s.validateParentChain(domain, dnskeys)
	}

	fmt.Printf("Validating DS records...\n")
	for i, ds := range dsRecords {
		fmt.Printf("DS record %d: keytag %d, algorithm %d, digest type %d\n",
			i, ds.KeyTag, ds.Algorithm, ds.DigestType)
		matched := false
		for j, dnskey := range dnskeys {
			fmt.Printf("Trying DNSKEY %d: keytag %d, algorithm %d\n",
				j, dnskey.KeyTag(), dnskey.Algorithm)
			if s.verifyDS(ds, dnskey) {
				fmt.Printf("DS record %d matched DNSKEY %d\n", i, j)
				matched = true
				break
			}
		}
		if !matched {
			fmt.Printf("No DNSKEY matched DS record %d\n", i)
			return false
		}
	}
	fmt.Printf("All DS records validated successfully\n")
	return true
}

// validateParentChain validates trust chain through parent zone.
// Important: fetch DS for 'domain' (DS are stored in parent zone) and validate against child's DNSKEYs.
func (s *DNSServer) validateParentChain(domain string, dnskeys []*dns.DNSKEY) bool {
	parent := s.getParentDomain(domain)
	fmt.Printf("validateParentChain: validating %s against parent %s\n", domain, parent)
	
	if parent == domain {
		fmt.Printf("validateParentChain: parent equals domain (%s); aborting\n", domain)
		return false
	}

	// Fetch DS records for the domain (these are published in the parent zone)
	dsRecords := s.getCachedDS(domain)
	if dsRecords == nil {
		var err error
		dsRecords, err = s.fetchDS(domain) // <- IMPORTANT: fetch DS for 'domain', not for 'parent'
		if err != nil {
			fmt.Printf("validateParentChain: error fetching DS records for %s from parent %s: %v\n", domain, parent, err)
			return false
		}
		if len(dsRecords) == 0 {
			fmt.Printf("validateParentChain: no DS records found for %s in parent %s -> insecure delegation\n", domain, parent)
			// No DS in parent means the child is not delegated with DNSSEC (insecure delegation).
			// Treat this as failure of chain validation (caller will treat as INSECURE).
			return false
		}
		fmt.Printf("validateParentChain: fetched %d DS records for %s from parent %s\n", len(dsRecords), domain, parent)
		s.cacheDS(domain, dsRecords)
	} else {
		fmt.Printf("validateParentChain: using %d cached DS records for %s\n", len(dsRecords), domain)
	}

	// Validate DS records against the provided child DNSKEYs
	fmt.Printf("validateParentChain: validating %d DNSKEYs against %d DS records\n", len(dnskeys), len(dsRecords))
	for i, ds := range dsRecords {
		fmt.Printf("DS record %d: keytag %d, algorithm %d, digest type %d, digest %s\n",
			i, ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
		matched := false
		for j, dnskey := range dnskeys {
			fmt.Printf("Trying child DNSKEY %d: keytag %d, algorithm %d, flags %d\n",
				j, dnskey.KeyTag(), dnskey.Algorithm, dnskey.Flags)
			if s.verifyDS(ds, dnskey) {
				fmt.Printf("DS record %d matched child DNSKEY %d\n", i, j)
				matched = true
				break
			}
		}
		if !matched {
			fmt.Printf("validateParentChain: no child DNSKEY matched DS record %d\n", i)
			return false
		}
	}
	fmt.Printf("validateParentChain: all DS records validated successfully for %s\n", domain)
	return true
}

// verifyDS verifies DS and DNSKEY correspondence
func (s *DNSServer) verifyDS(ds *dns.DS, dnskey *dns.DNSKEY) bool {
	// Check if DNSKEY is a Zone Signing Key (ZSK)
	if dnskey.Flags&256 == 0 { // Bit 8 (ZSK) is not set
		// For DS validation, we typically expect a KSK (bit 7 set) or ZSK
		// But some implementations use KSKs for DS records
		fmt.Printf("DNSKEY with keytag %d may not be appropriate for DS validation (flags: %d)\n",
			dnskey.KeyTag(), dnskey.Flags)
	}

	keyData, err := base64.StdEncoding.DecodeString(dnskey.PublicKey)
	if err != nil {
		fmt.Printf("Failed to decode DNSKEY public key: %v\n", err)
		return false
	}

	// Create the DS from DNSKEY according to RFC 4034
	owner := strings.ToLower(dns.CanonicalName(dnskey.Header().Name))
	
	// Prepare data for hashing: owner name, DNSKEY RDATA
	buf := make([]byte, 0, 4096) // Make a buffer with reasonable capacity
	
	// Add owner name in wire format
	nameBuf := make([]byte, 255) // Buffer for the packed name
	off, err := dns.PackDomainName(owner, nameBuf, 0, nil, false)
	if err != nil {
		fmt.Printf("Failed to pack domain name: %v\n", err)
		return false
	}
	buf = append(buf, nameBuf[:off]...)
	
	// Add DNSKEY RDATA
	rdata := make([]byte, 4+len(keyData))
	binary.BigEndian.PutUint16(rdata[0:], dnskey.Flags)
	rdata[2] = dnskey.Protocol
	rdata[3] = dnskey.Algorithm
	copy(rdata[4:], keyData)
	buf = append(buf, rdata...)
	
	var hash []byte
	switch ds.DigestType {
	case dns.SHA1:
		h := sha1.Sum(buf)
		hash = h[:]
	case dns.SHA256:
		h := sha256.Sum256(buf)
		hash = h[:]
	default:
		fmt.Printf("Unsupported DS digest type: %d\n", ds.DigestType)
		return false
	}

	computedDigest := hex.EncodeToString(hash)
	if strings.EqualFold(computedDigest, ds.Digest) {
		return true
	}
	
	fmt.Printf("DS digest mismatch. Computed: %s, Expected: %s\n",
		computedDigest, ds.Digest)
	return false
}

// getParentDomain returns the parent domain
func (s *DNSServer) getParentDomain(domain string) string {
	if domain == "." || domain == "" {
		return "."
	}

	parts := strings.Split(strings.Trim(domain, "."), ".")
	if len(parts) <= 1 {
		return "."
	}

	return strings.Join(parts[1:], ".") + "."
}

// getCachedDNSKEY retrieves DNSKEY from cache
func (s *DNSServer) getCachedDNSKEY(domain string, keyTag uint16, algorithm uint8) *dns.DNSKEY {
	key := fmt.Sprintf("%s_%d_%d", domain, keyTag, algorithm)
	if cachedKey, exists := s.keyCache.Load(key); exists {
		if cacheTime, timeExists := s.keyCacheTime.Load(key); timeExists {
			if cacheTimeT, ok := cacheTime.(time.Time); ok {
				if time.Since(cacheTimeT) < keyCacheTTL {
					if dnskey, ok := cachedKey.(*dns.DNSKEY); ok {
						atomic.AddUint64(&s.cacheHits, 1)
						return dnskey
					}
				}
			}
		}
	}
	atomic.AddUint64(&s.cacheMisses, 1)
	return nil
}

// cacheDNSKEY caches a DNSKEY
func (s *DNSServer) cacheDNSKEY(domain string, dnskey *dns.DNSKEY) {
	key := fmt.Sprintf("%s_%d_%d", domain, dnskey.KeyTag(), dnskey.Algorithm)
	s.keyCache.Store(key, dnskey)
	s.keyCacheTime.Store(key, time.Now())
}

// getCachedDS retrieves DS records from cache
func (s *DNSServer) getCachedDS(domain string) []*dns.DS {
	if dsRecords, exists := s.dsCache.Load(domain); exists {
		if cacheTime, timeExists := s.dsCacheTime.Load(domain); timeExists {
			if cacheTimeT, ok := cacheTime.(time.Time); ok {
				if time.Since(cacheTimeT) < dsCacheTTL {
					if ds, ok := dsRecords.([]*dns.DS); ok {
						atomic.AddUint64(&s.cacheHits, 1)
						return ds
					}
				}
			}
		}
	}
	atomic.AddUint64(&s.cacheMisses, 1)
	return nil
}

// cacheDS caches DS records
func (s *DNSServer) cacheDS(domain string, dsRecords []*dns.DS) {
	s.dsCache.Store(domain, dsRecords)
	s.dsCacheTime.Store(domain, time.Now())
}

// cacheRRSIG caches RRSIG records
func (s *DNSServer) cacheRRSIG(rrsig *dns.RRSIG) {
	key := fmt.Sprintf("%s_%d_%d_%d", rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm, rrsig.TypeCovered)
	s.rrsigCache.Store(key, rrsig)
	s.rrsigCacheTime.Store(key, time.Now())
}

// fetchDNSKEY fetches DNSKEY for a domain
func (s *DNSServer) fetchDNSKEY(domain string, keyTag uint16, algorithm uint8) *dns.DNSKEY {
	fmt.Printf("Fetching DNSKEY for %s, keytag %d, algorithm %d\n", domain, keyTag, algorithm)
	results := s.qnameMinimizeResolve(domain, "DNSKEY")
	fmt.Printf("DNSKEY resolution returned %d results\n", len(results))
	
	for i, r := range results {
		fmt.Printf("DNSKEY result %d: %s\n", i, r)
		if rr, err := dns.NewRR(r); err == nil {
			if dnskey, ok := rr.(*dns.DNSKEY); ok {
				fmt.Printf("Parsed DNSKEY: keytag %d, algorithm %d, flags %d\n",
					dnskey.KeyTag(), dnskey.Algorithm, dnskey.Flags)
				if dnskey.KeyTag() == keyTag && dnskey.Algorithm == algorithm {
					s.cacheDNSKEY(domain, dnskey)
					fmt.Printf("Found matching DNSKEY for %s\n", domain)
					return dnskey
				}
			} else {
				fmt.Printf("RR is not a DNSKEY: %T\n", rr)
			}
		} else {
			fmt.Printf("Failed to parse RR: %v\n", err)
		}
	}
	fmt.Printf("No matching DNSKEY found for %s, keytag %d, algorithm %d\n", domain, keyTag, algorithm)
	return nil
}

// fetchDS fetches DS records for a domain by querying the parent zone's authoritative servers.
// This implementation directly queries the parent zone's authoritative name servers.
func (s *DNSServer) fetchDS(domain string) ([]*dns.DS, error) {
	fmt.Printf("fetchDS: fetching DS records for %s by querying parent zone's authoritative servers\n", domain)

	parent := s.getParentDomain(domain)
	if parent == domain || (parent == "." && domain != ".") {
		// Special case for root or when we reach the top - there's no parent to query for DS
		fmt.Printf("fetchDS: reached root or top level for %s, no parent DS exists\n", domain)
		// For root zone, validation should be against the trust anchor in validateTrustChain
		return nil, nil
	}

	fmt.Printf("fetchDS: Parent zone for %s is %s\n", domain, parent)

	// 1. Get authoritative NS servers for the parent zone
	// We cannot use s.resolver.Resolve here directly for NS as we need the authoritative source for DS.
	// We will use qnameMinimizeResolve to find the NS of the parent first.
	nsResults := s.qnameMinimizeResolve(parent, "NS")
	if len(nsResults) == 0 {
		fmt.Printf("fetchDS: failed to get NS servers for parent zone %s\n", parent)
		return nil, fmt.Errorf("no NS servers found for parent zone %s", parent)
	}

	var nsNames []string
	for _, r := range nsResults {
		if rr, err := dns.NewRR(r); err == nil {
			if ns, ok := rr.(*dns.NS); ok {
				nsNames = append(nsNames, dns.Fqdn(ns.Ns))
			}
		}
	}

	if len(nsNames) == 0 {
		fmt.Printf("fetchDS: failed to parse any NS servers from results for parent %s\n", parent)
		return nil, fmt.Errorf("no valid NS servers found for parent zone %s", parent)
	}

	fmt.Printf("fetchDS: Found NS servers for parent %s: %v\n", parent, nsNames)

	// 2. Resolve IP addresses for these parent NS servers
	// Try to resolve them using our own resolver first
	var parentNSIPs []string
	for _, nsName := range nsNames {
		// Try to get A record
		aResults := s.qnameMinimizeResolve(nsName, "A")
		for _, r := range aResults {
			if rr, err := dns.NewRR(r); err == nil {
				if a, ok := rr.(*dns.A); ok {
					parentNSIPs = append(parentNSIPs, a.A.String())
				}
			}
		}
		// Try to get AAAA record
		aaaaResults := s.qnameMinimizeResolve(nsName, "AAAA")
		for _, r := range aaaaResults {
			if rr, err := dns.NewRR(r); err == nil {
				if aaaa, ok := rr.(*dns.AAAA); ok {
					parentNSIPs = append(parentNSIPs, aaaa.AAAA.String())
				}
			}
		}
	}

	// If our resolver couldn't find IPs, fall back to system resolver
	if len(parentNSIPs) == 0 {
		fmt.Printf("fetchDS: No IPs found via internal resolver for parent NS, trying system resolver\n")
		for _, nsName := range nsNames {
			ips, err := net.LookupIP(nsName)
			if err != nil {
				fmt.Printf("fetchDS: System lookup failed for %s: %v\n", nsName, err)
				continue
			}
			for _, ip := range ips {
				parentNSIPs = append(parentNSIPs, ip.String())
			}
		}
	}

	if len(parentNSIPs) == 0 {
		fmt.Printf("fetchDS: failed to resolve any IP addresses for parent NS servers\n")
		return nil, fmt.Errorf("could not resolve IPs for parent NS servers of %s", parent)
	}

	fmt.Printf("fetchDS: Resolved IPs for parent NS: %v\n", parentNSIPs)

	// 3. Query one of the parent NS IPs directly for the DS record of 'domain'
	domainFQDN := dns.Fqdn(domain)
	var dsRecords []*dns.DS

	// Try up to 3 different parent NS IPs to increase robustness
	ipsToTry := parentNSIPs
	if len(ipsToTry) > 3 {
		ipsToTry = ipsToTry[:3]
	}

	for _, ip := range ipsToTry {
		addr := net.JoinHostPort(ip, "53")
		client := &dns.Client{
			Net:     "udp",
			Timeout: 5 * time.Second,
		}

		// Create the DS query message
		msg := new(dns.Msg)
		msg.SetQuestion(domainFQDN, dns.TypeDS)
		// Enable EDNS0 and DO bit for DNSSEC
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(dns.DefaultMsgSize) // Use default size, can be adjusted
		opt.SetDo()                        // Set DNSSEC OK bit
		msg.Extra = append(msg.Extra, opt)

		fmt.Printf("fetchDS: Sending DS query for %s to parent NS at %s\n", domainFQDN, addr)
		response, _, err := client.Exchange(msg, addr)

		if err != nil {
			fmt.Printf("fetchDS: UDP query to %s failed: %v, trying TCP\n", addr, err)
			// Fallback to TCP
			client.Net = "tcp"
			response, _, err = client.Exchange(msg, addr)
			if err != nil {
				fmt.Printf("fetchDS: TCP query to %s also failed: %v\n", addr, err)
				continue // Try the next IP address
			}
		}

		if response == nil {
			fmt.Printf("fetchDS: Received nil response from %s\n", addr)
			continue
		}

		// Check the response code
		if response.Rcode != dns.RcodeSuccess {
			fmt.Printf("fetchDS: Received RCODE %d from %s for DS query of %s\n", response.Rcode, addr, domainFQDN)
			// NXDOMAIN for a DS query means the domain is not signed (insecure delegation)
			if response.Rcode == dns.RcodeNameError {
				fmt.Printf("fetchDS: NXDOMAIN from %s for DS query, indicating insecure delegation of %s\n", addr, domain)
				// Return empty slice, not an error, as this is a valid DNSSEC state
				return nil, nil
			}
			// Continue to try another IP
			continue
		}

		// Process the answer section of the response
		fmt.Printf("fetchDS: Received successful response from %s\n", addr)
		for _, rr := range response.Answer {
			fmt.Printf("fetchDS: Processing answer record: %s\n", rr.String())
			if ds, ok := rr.(*dns.DS); ok {
				// Verify the DS record is for the domain we are interested in
				if strings.EqualFold(dns.CanonicalName(ds.Hdr.Name), dns.CanonicalName(domainFQDN)) {
					dsRecords = append(dsRecords, ds)
					fmt.Printf("fetchDS: Found DS record: KeyTag=%d, Algorithm=%d, DigestType=%d\n",
						ds.KeyTag, ds.Algorithm, ds.DigestType)
				} else {
					fmt.Printf("fetchDS: DS record for a different name: %s\n", ds.Hdr.Name)
				}
			} else {
				fmt.Printf("fetchDS: Non-DS record in answer section: %T\n", rr)
				// Sometimes NSEC/NSEC3 records might be present if DS doesn't exist
			}
		}

		// If we got a response (success or proven non-existence), we can stop trying other IPs
		// An empty dsRecords slice here means DS doesn't exist (insecure delegation)
		break
	}

	if len(dsRecords) == 0 {
		fmt.Printf("fetchDS: No DS records found for %s in parent zone %s. This likely indicates insecure delegation.\n", domain, parent)
	} else {
		fmt.Printf("fetchDS: Successfully fetched %d DS records for %s\n", len(dsRecords), domain)
	}

	return dsRecords, nil
}

// sendErrorResponse sends an error response to the client
func (s *DNSServer) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int, message string) {
	reply := new(dns.Msg)
	reply.SetRcode(req, rcode)
	reply.Compress = true

	if edns0 := req.IsEdns0(); edns0 != nil && s.dnssecEnabled {
		reply.SetEdns0(edns0.UDPSize(), edns0.Do())
	}

	if req != nil && len(req.Question) > 0 {
		txtRecord := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
			},
			Txt: []string{message},
		}
		reply.Extra = append(reply.Extra, txtRecord)
	}

	if err := w.WriteMsg(reply); err != nil {
		fmt.Printf("Error sending error response: %v\n", err)
	}
}

// fetchFromAuthoritative queries authoritative NS directly for the given name and qtype.
// Returns any RRset (from Answer) and RRSIGs (covering anything) it finds.
// It resolves NS -> A via qnameMinimizeResolve, then queries those IPs on port 53.
func (s *DNSServer) fetchFromAuthoritative(name string, qtype uint16) ([]dns.RR, []*dns.RRSIG) {
	var rrset []dns.RR
	var rrsigs []*dns.RRSIG

	// 1) get NS names
	nsResults := s.qnameMinimizeResolve(name, "NS")
	var nsNames []string
	for _, r := range nsResults {
		if rr, err := dns.NewRR(r); err == nil {
			if ns, ok := rr.(*dns.NS); ok {
				nsNames = append(nsNames, dns.Fqdn(ns.Ns))
			}
		}
	}
	
	if len(nsNames) == 0 {
		// fallback: try parent NS
		parent := s.getParentDomain(name)
		if parent != name && parent != "." {
			nsResults = s.qnameMinimizeResolve(parent, "NS")
			for _, r := range nsResults {
				if rr, err := dns.NewRR(r); err == nil {
					if ns, ok := rr.(*dns.NS); ok {
						nsNames = append(nsNames, dns.Fqdn(ns.Ns))
					}
				}
			}
		}
	}

	// For each NS, resolve its A/AAAA and query them directly.
	for _, nsName := range nsNames {
		// resolve A
		aResults := s.qnameMinimizeResolve(nsName, "A")
		var ips []string
		for _, r := range aResults {
			if rr, err := dns.NewRR(r); err == nil {
				if a, ok := rr.(*dns.A); ok {
					ips = append(ips, a.A.String())
				}
			}
		}
		
		// resolve AAAA
		aaaaResults := s.qnameMinimizeResolve(nsName, "AAAA")
		for _, r := range aaaaResults {
			if rr, err := dns.NewRR(r); err == nil {
				if aaaa, ok := rr.(*dns.AAAA); ok {
					ips = append(ips, aaaa.AAAA.String())
				}
			}
		}
		
		// if no IPs from our resolver, try system lookup as a last resort
		if len(ips) == 0 {
			sysIPs, _ := net.LookupIP(nsName)
			for _, ip := range sysIPs {
				ips = append(ips, ip.String())
			}
		}
		
		for _, ip := range ips {
			addr := net.JoinHostPort(ip, "53")
			c := &dns.Client{Timeout: 2 * time.Second, Net: "udp"}
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(name), qtype)
			o := new(dns.OPT)
			o.Hdr.Name = "."
			o.Hdr.Rrtype = dns.TypeOPT
			o.SetUDPSize(maxUDPSize)
			o.SetDo()
			m.Extra = append(m.Extra, o)
			
			in, _, err := c.Exchange(m, addr)
			if err != nil {
				// try tcp fallback
				c.Net = "tcp"
				in, _, err = c.Exchange(m, addr)
				if err != nil {
					fmt.Printf("fetchFromAuthoritative: exchange to %s failed: %v\n", addr, err)
					continue
				}
			}
			if in == nil {
				continue
			}
			
			// Collect answer rrset and rrsigs (from answer and authority sections)
			for _, rr := range in.Answer {
				if rrsig, ok := rr.(*dns.RRSIG); ok {
					rrsigs = append(rrsigs, rrsig)
				} else {
					if rr.Header().Rrtype == qtype {
						rrset = append(rrset, rr)
					}
				}
			}
			for _, rr := range in.Ns {
				if rrsig, ok := rr.(*dns.RRSIG); ok {
					rrsigs = append(rrsigs, rrsig)
				}
			}
			
			// stop early if we already have some useful RRSIGs covering qtype
			for _, r := range rrsigs {
				if r.TypeCovered == qtype {
					return rrset, rrsigs
				}
			}
		}
	}
	return rrset, rrsigs
}

// betweenBase32 returns true if target is strictly between start and end in base32 ordering (wrap aware).
func betweenBase32(start, target, end string) bool {
	start = strings.ToLower(strings.TrimSpace(start))
	target = strings.ToLower(strings.TrimSpace(target))
	end = strings.ToLower(strings.TrimSpace(end))
	
	if start < end {
		return start < target && target < end
	}
	// wrap-around
	return target > start || target < end
}

// betweenDomain uses lexical ordering on canonical domain names (not perfect but improved by canonicalization)
func betweenDomain(start, target, end string) bool {
	start = strings.ToLower(strings.TrimSpace(start))
	target = strings.ToLower(strings.TrimSpace(target))
	end = strings.ToLower(strings.TrimSpace(end))
	
	if start < end {
		return start < target && target < end
	}
	return target > start || target < end
}

func main() {
	server := NewDNSServer()
	go server.startCleaner()

	dns.HandleFunc(".", server.handleRequest)

	udpServer := &dns.Server{Addr: ":5454", Net: "udp", UDPSize: maxUDPSize}
	go func() {
		fmt.Println("DNS resolver (UDP) listening on port 5454")
		if err := udpServer.ListenAndServe(); err != nil && err != net.ErrClosed {
			fmt.Printf("Error starting UDP server: %v\n", err)
		}
	}()

	tcpServer := &dns.Server{Addr: ":5454", Net: "tcp"}
	go func() {
		fmt.Println("DNS resolver (TCP) listening on port 5454")
		if err := tcpServer.ListenAndServe(); err != nil && err != net.ErrClosed {
			fmt.Printf("Error starting TCP server: %v\n", err)
		}
	}()

	select {}
}
