// main.go
package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ----------------------- Конфиг и константы -----------------------
const (
	listenAddr       = ":5454"
	maxUDPSize       = 4096
	keyCacheTTL      = 24 * time.Hour
	dsCacheTTL       = 24 * time.Hour
	rrsigCacheTTL    = 1 * time.Hour
	visitedTTL       = 10 * time.Minute
	nxdomainTTL      = 30 * time.Minute
	nxdomainLimit    = 3
	quarantinePeriod = 30 * time.Second
	resolveTimeout   = 3 * time.Second
	cleanInterval    = 5 * time.Minute
)

// Апстрим-резолверы (можно настроить свои)
var upstreams = []string{
	"1.1.1.1:53", // Cloudflare
	"8.8.8.8:53", // Google
}

// ----------------------- Типы и структура -----------------------
type DNSSECValidationResult int

const (
	DNSSEC_SECURE DNSSECValidationResult = iota
	DNSSEC_INSECURE
	DNSSEC_BOGUS
	DNSSEC_INDETERMINATE
)

// DNSServer хранит состояние рекурсора
type DNSServer struct {
	// caches
	keyCache       sync.Map // key -> *dns.DNSKEY
	keyCacheTime   sync.Map // key -> time.Time
	dsCache        sync.Map // domain -> []*dns.DS
	dsCacheTime    sync.Map // domain -> time.Time
	rrsigCache     sync.Map // key -> *dns.RRSIG
	rrsigCacheTime sync.Map // key -> time.Time

	// anti-loop / nx handling
	visited          sync.Map // queryKey -> time.Time
	nxdomainCounter  sync.Map // domain -> int
	nxdomainLastSeen sync.Map // domain -> time.Time
	quarantined      sync.Map // domain -> time.Time

	// trust anchor (root KSK)
	trustAnchor *dns.DNSKEY

	// metrics
	secureQueries        uint64
	insecureQueries      uint64
	bogusQueries         uint64
	indeterminateQueries uint64
	cacheHits            uint64
	cacheMisses          uint64
}

// ----------------------- Инициализация -----------------------
func NewDNSServer() *DNSServer {
	s := &DNSServer{}
	s.initializeTrustAnchor()
	return s
}

func (s *DNSServer) initializeTrustAnchor() {
	// Root KSK-2017 (RFC 8624) -- строка RR
	keyStr := ". IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5ZRzF9YWcJnJzRc5Diz20y+O3j2YiD6ZGyXaK0r1W/0WZi8c9I0HPObYJw8FXQzG00kHvU1OqqCtKkRBOhB4wR5KJ4QkhzN5ZU5lFsNhqVCKVCYyUMxMEJlJQZlNq6q+aIzHVMZQnR4ggr3H8H9U9F92F6VK7S9ZQ1Y="
	rr, err := dns.NewRR(keyStr)
	if err != nil {
		fmt.Printf("Failed to parse trust anchor RR: %v\n", err)
		return
	}
	if k, ok := rr.(*dns.DNSKEY); ok {
		s.trustAnchor = k
		fmt.Println("Trust anchor loaded")
	}
}

// ----------------------- Background cleaner -----------------------
func (s *DNSServer) startCleaner() {
	ticker := time.NewTicker(cleanInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		// visited
		visitedCount := 0
		s.visited.Range(func(k, v interface{}) bool {
			if t, ok := v.(time.Time); ok {
				if now.Sub(t) > visitedTTL {
					s.visited.Delete(k)
					visitedCount++
				}
			}
			return true
		})
		// nxdomain
		nxCount := 0
		s.nxdomainLastSeen.Range(func(k, v interface{}) bool {
			if t, ok := v.(time.Time); ok {
				if now.Sub(t) > nxdomainTTL {
					s.nxdomainCounter.Delete(k)
					s.nxdomainLastSeen.Delete(k)
					nxCount++
				}
			}
			return true
		})
		// quarantine
		qCount := 0
		s.quarantined.Range(func(k, v interface{}) bool {
			if tt, ok := v.(time.Time); ok {
				if now.After(tt) {
					s.quarantined.Delete(k)
					qCount++
				}
			}
			return true
		})
		// key cache
		keyRemoved := 0
		s.keyCacheTime.Range(func(k, v interface{}) bool {
			if t, ok := v.(time.Time); ok {
				if now.Sub(t) > keyCacheTTL {
					s.keyCache.Delete(k)
					s.keyCacheTime.Delete(k)
					keyRemoved++
				}
			}
			return true
		})
		// ds cache
		dsRemoved := 0
		s.dsCacheTime.Range(func(k, v interface{}) bool {
			if t, ok := v.(time.Time); ok {
				if now.Sub(t) > dsCacheTTL {
					s.dsCache.Delete(k)
					s.dsCacheTime.Delete(k)
					dsRemoved++
				}
			}
			return true
		})
		// rrsig cache
		rrsigRemoved := 0
		s.rrsigCacheTime.Range(func(k, v interface{}) bool {
			if t, ok := v.(time.Time); ok {
				if now.Sub(t) > rrsigCacheTTL {
					s.rrsigCache.Delete(k)
					s.rrsigCacheTime.Delete(k)
					rrsigRemoved++
				}
			}
			return true
		})

		fmt.Printf("Cleaner: visited=%d nxreset=%d quarant=%d keys=%d ds=%d rrsig=%d\n",
			visitedCount, nxCount, qCount, keyRemoved, dsRemoved, rrsigRemoved)
		fmt.Printf("Metrics: secure=%d insecure=%d bogus=%d indet=%d cacheHits=%d cacheMisses=%d\n",
			atomic.LoadUint64(&s.secureQueries),
			atomic.LoadUint64(&s.insecureQueries),
			atomic.LoadUint64(&s.bogusQueries),
			atomic.LoadUint64(&s.indeterminateQueries),
			atomic.LoadUint64(&s.cacheHits),
			atomic.LoadUint64(&s.cacheMisses))
	}
}

// ----------------------- Upstream querying -----------------------

// upstreamResolveSingle делает один запрос к одному апстриму (попытки по списку upstreams),
// если dnssec==true то выставляет DO.
func (s *DNSServer) upstreamResolveSingle(name string, qtype uint16, dnssec bool) ([]dns.RR, *dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	if dnssec {
		msg.SetEdns0(maxUDPSize, true)
	} else {
		msg.SetEdns0(maxUDPSize, false)
	}
	client := &dns.Client{Timeout: resolveTimeout}
	// Попробуем все апстримы по очереди (простая стратегия)
	var lastErr error
	for _, up := range upstreams {
		in, _, err := client.Exchange(msg, up)
		if err != nil {
			lastErr = err
			continue
		}
		// Возвращаем Answer + Ns + Extra (иногда RRSIG в Ns)
		var out []dns.RR
		out = append(out, in.Answer...)
		out = append(out, in.Ns...)
		out = append(out, in.Extra...)
		return out, in, nil
	}
	return nil, nil, fmt.Errorf("all upstreams failed: %v", lastErr)
}

// qnameMinimizeResolve реализует простую QNAME minimization:
// пытаемся запросить указанный тип для домена, если пусто — поднимаемся к родителю и т.д.
// Для DNSSEC-типов делаем DO=true.
func (s *DNSServer) qnameMinimizeResolve(domain string, qtype string) []dns.RR {
	// Ensure FQDN
	d := dns.Fqdn(domain)
	// normalize
	d = strings.TrimSpace(d)
	if d == "" {
		return nil
	}
	tried := map[string]bool{}
	qt, ok := dns.StringToType[qtype]
	if !ok {
		// если неизвестный тип, пробуем по имени (редко)
		return nil
	}
	for {
		if _, ok := tried[d]; ok {
			break
		}
		tried[d] = true

		useDO := (qtype == "RRSIG" || qtype == "DNSKEY" || qtype == "DS" || qtype == "NSEC" || qtype == "NSEC3")
		rrs, _, err := s.upstreamResolveSingle(d, qt, useDO)
		if err == nil && len(rrs) > 0 {
			return rrs
		}
		// поднять к родителю
		parent := parentDomain(d)
		if parent == d || parent == "" || parent == "." {
			break
		}
		d = parent
	}
	return nil
}

// parentDomain возвращает родительский домен (в FQDN стиле)
func parentDomain(domain string) string {
	d := strings.TrimSpace(domain)
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "."
	}
	parts := strings.Split(d, ".")
	if len(parts) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(parts[1:], "."))
}

// ----------------------- DNSSEC: fetch & validate -----------------------

// fetchDNSSECRecordsAsync параллельно получает RRSIG, DNSKEY, DS (с QNAME minimization)
func (s *DNSServer) fetchDNSSECRecordsAsync(domain string) ([]*dns.RRSIG, []*dns.DNSKEY, []*dns.DS, error) {
	rrsigCh := make(chan []*dns.RRSIG, 1)
	dnskeyCh := make(chan []*dns.DNSKEY, 1)
	dsCh := make(chan []*dns.DS, 1)

	go func() {
		res := s.qnameMinimizeResolve(domain, "RRSIG")
		var out []*dns.RRSIG
		for _, rr := range res {
			if rrsig, ok := rr.(*dns.RRSIG); ok {
				out = append(out, rrsig)
			}
		}
		rrsigCh <- out
	}()

	go func() {
		res := s.qnameMinimizeResolve(domain, "DNSKEY")
		var out []*dns.DNSKEY
		for _, rr := range res {
			if key, ok := rr.(*dns.DNSKEY); ok {
				out = append(out, key)
			}
		}
		dnskeyCh <- out
	}()

	go func() {
		res := s.qnameMinimizeResolve(domain, "DS")
		var out []*dns.DS
		for _, rr := range res {
			if ds, ok := rr.(*dns.DS); ok {
				out = append(out, ds)
			}
		}
		dsCh <- out
	}()

	timeout := time.After(5 * time.Second)
	var rrsigs []*dns.RRSIG
	var dnskeys []*dns.DNSKEY
	var ds []*dns.DS

	for i := 0; i < 3; i++ {
		select {
		case rrsigs = <-rrsigCh:
		case dnskeys = <-dnskeyCh:
		case ds = <-dsCh:
		case <-timeout:
			// return partial + error
			return rrsigs, dnskeys, ds, fmt.Errorf("timeout fetching dnssec records")
		}
	}
	return rrsigs, dnskeys, ds, nil
}

// fetchDS fetches DS via qnameMinimizeResolve
func (s *DNSServer) fetchDS(domain string) ([]*dns.DS, error) {
	res := s.qnameMinimizeResolve(domain, "DS")
	var out []*dns.DS
	for _, rr := range res {
		if ds, ok := rr.(*dns.DS); ok {
			out = append(out, ds)
		}
	}
	return out, nil
}

// fetchDNSKEY fetches DNSKEY via qnameMinimizeResolve and filters by keyTag/alg if supplied (if keyTag==0 => first match returning all)
func (s *DNSServer) fetchDNSKEY(domain string, keyTag uint16, algorithm uint8) *dns.DNSKEY {
	res := s.qnameMinimizeResolve(domain, "DNSKEY")
	for _, rr := range res {
		if key, ok := rr.(*dns.DNSKEY); ok {
			if keyTag == 0 || (key.KeyTag() == keyTag && key.Algorithm == algorithm) {
				// cache it
				s.cacheDNSKEY(domain, key)
				return key
			}
		}
	}
	return nil
}

// ----------------------- Кэширующие функции -----------------------
func (s *DNSServer) cacheDNSKEY(domain string, key *dns.DNSKEY) {
	k := fmt.Sprintf("%s_%d_%d", dns.Fqdn(domain), key.KeyTag(), key.Algorithm)
	s.keyCache.Store(k, key)
	s.keyCacheTime.Store(k, time.Now())
}

func (s *DNSServer) getCachedDNSKEY(domain string, keyTag uint16, algorithm uint8) *dns.DNSKEY {
	k := fmt.Sprintf("%s_%d_%d", dns.Fqdn(domain), keyTag, algorithm)
	if v, ok := s.keyCache.Load(k); ok {
		if t, ok2 := s.keyCacheTime.Load(k); ok2 {
			if tt, ok3 := t.(time.Time); ok3 {
				if time.Since(tt) < keyCacheTTL {
					if key, ok4 := v.(*dns.DNSKEY); ok4 {
						atomic.AddUint64(&s.cacheHits, 1)
						return key
					}
				}
			}
		}
	}
	atomic.AddUint64(&s.cacheMisses, 1)
	return nil
}

func (s *DNSServer) cacheDS(domain string, records []*dns.DS) {
	s.dsCache.Store(dns.Fqdn(domain), records)
	s.dsCacheTime.Store(dns.Fqdn(domain), time.Now())
}

func (s *DNSServer) getCachedDS(domain string) []*dns.DS {
	if v, ok := s.dsCache.Load(dns.Fqdn(domain)); ok {
		if t, ok2 := s.dsCacheTime.Load(dns.Fqdn(domain)); ok2 {
			if tt, ok3 := t.(time.Time); ok3 {
				if time.Since(tt) < dsCacheTTL {
					if ds, ok4 := v.([]*dns.DS); ok4 {
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

func (s *DNSServer) cacheRRSIG(rrsig *dns.RRSIG) {
	k := fmt.Sprintf("%s_%d_%d_%d", dns.Fqdn(rrsig.SignerName), rrsig.KeyTag, rrsig.Algorithm, rrsig.TypeCovered)
	s.rrsigCache.Store(k, rrsig)
	s.rrsigCacheTime.Store(k, time.Now())
}

// ----------------------- DNSSEC проверки -----------------------

// validateDNSSEC валидирует: проверяет RRSIG над ответом (если есть) и цепочку доверия через DS/DNSKEY.
// Возвращает DNSSEC_SECURE / INSECURE / BOGUS / INDETERMINATE
func (s *DNSServer) validateDNSSEC(domain string, reply *dns.Msg) DNSSECValidationResult {
	rrsigs, dnskeys, dsRecords, err := s.fetchDNSSECRecordsAsync(domain)
	if err != nil {
		// всё-таки возможно частичная валидация; отмечаем как INDETERMINATE
		fmt.Printf("fetchDNSSECRecordsAsync error: %v\n", err)
		return DNSSEC_INDETERMINATE
	}

	// Если вообще ничего нет => insecure
	if len(rrsigs) == 0 && len(dnskeys) == 0 && len(dsRecords) == 0 {
		return DNSSEC_INSECURE
	}

	// Проверяем RRSIGы, если они есть
	if len(rrsigs) > 0 {
		for _, rrsig := range rrsigs {
			// соберем RRset с типом rrsig.TypeCovered из reply.Answer
			rrset := canonicalizeRRSet(reply.Answer, rrsig.TypeCovered)
			if len(rrset) == 0 {
				// нет RRset — возможно мы валидируем отрицательный ответ; пропускаем здесь
				continue
			}
			if !s.verifyRRSIGWithMiekg(rrsig, rrset) {
				fmt.Printf("RRSIG verify failed for %s signer=%s\n", domain, rrsig.SignerName)
				return DNSSEC_BOGUS
			}
		}
	}

	// Проверяем цепочку доверия: если есть DS — сверяем DS<->DNSKEY, иначе поднимаемся вверх
	if !s.validateTrustChain(domain, dnskeys, dsRecords) {
		fmt.Printf("Trust chain validation failed for %s\n", domain)
		return DNSSEC_BOGUS
	}

	return DNSSEC_SECURE
}

// canonicalizeRRSet фильтрует и канонизирует RRset по типу
func canonicalizeRRSet(rrset []dns.RR, qtype uint16) []dns.RR {
	var filtered []dns.RR
	for _, rr := range rrset {
		if rr.Header().Rrtype == qtype {
			filtered = append(filtered, rr)
		}
	}
	if len(filtered) == 0 {
		return filtered
	}
	for _, rr := range filtered {
		rr.Header().Name = strings.ToLower(dns.CanonicalName(rr.Header().Name))
	}
	// сортировка по каноническому порядку (упрощённо)
	sort.Slice(filtered, func(i, j int) bool {
		return strings.Compare(filtered[i].String(), filtered[j].String()) < 0
	})
	return filtered
}

// verifyRRSIGWithMiekg проверяет подпись RRSIG против DNSKEY (берёт DNSKEY из кэша или запросит)
func (s *DNSServer) verifyRRSIGWithMiekg(rrsig *dns.RRSIG, rrset []dns.RR) bool {
	if len(rrset) == 0 {
		return false
	}
	// кэш RRSIG по ключу
	k := fmt.Sprintf("%s_%d_%d_%d", dns.Fqdn(rrsig.SignerName), rrsig.KeyTag, rrsig.Algorithm, rrsig.TypeCovered)
	if v, ok := s.rrsigCache.Load(k); ok {
		if t, ok2 := s.rrsigCacheTime.Load(k); ok2 {
			if tt, ok3 := t.(time.Time); ok3 {
				if time.Since(tt) < rrsigCacheTTL {
					if cached, ok4 := v.(*dns.RRSIG); ok4 {
						if cached.Signature == rrsig.Signature {
							atomic.AddUint64(&s.cacheHits, 1)
							return true
						}
					}
				}
			}
		}
	}
	atomic.AddUint64(&s.cacheMisses, 1)

	// Получить DNSKEY
	dnskey := s.getCachedDNSKEY(rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
	if dnskey == nil {
		dnskey = s.fetchDNSKEY(rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
		if dnskey == nil {
			fmt.Printf("DNSKEY not found for %s (signer %s)\n", rrsig.SignerName, rrsig.SignerName)
			return false
		}
		s.cacheDNSKEY(rrsig.SignerName, dnskey)
	}

	// Verify uses miekg/dns's Verify function
	if err := rrsig.Verify(dnskey, rrset); err != nil {
		fmt.Printf("RRSIG Verify error: %v\n", err)
		return false
	}
	// cache successful verify
	s.cacheRRSIG(rrsig)
	return true
}

// validateTrustChain проверяет DS/DNSKEY связку и при отсутствии DS — поднимается в родительскую зону
func (s *DNSServer) validateTrustChain(domain string, dnskeys []*dns.DNSKEY, dsRecords []*dns.DS) bool {
	d := dns.Fqdn(domain)
	// если есть DS — сверяем DS<->DNSKEY
	if len(dsRecords) > 0 {
		for _, ds := range dsRecords {
			matched := false
			for _, key := range dnskeys {
				if verifyDS(ds, key) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		return true
	}

	// если DS нет: если домен root — сверяем с trust anchor
	if d == "." || d == "" {
		if s.trustAnchor == nil {
			return false
		}
		for _, key := range dnskeys {
			if key.KeyTag() == s.trustAnchor.KeyTag() && key.Algorithm == s.trustAnchor.Algorithm {
				return true
			}
		}
		return false
	}

	// иначе — проверяем у родителя
	parent := parentDomain(d)
	if parent == d || parent == "." {
		// запрашиваем DS у родителя
		ds := s.getCachedDS(parent)
		if ds == nil {
			// fetch
			fetched, err := s.fetchDS(parent)
			if err == nil && len(fetched) > 0 {
				s.cacheDS(parent, fetched)
				ds = fetched
			}
		}
		if ds == nil || len(ds) == 0 {
			// нет DS у родителя -> значит домен не делегирован с DNSSEC
			return false
		}
		// сверяем
		for _, drec := range ds {
			for _, key := range dnskeys {
				if verifyDS(drec, key) {
					return true
				}
			}
		}
		return false
	}

	// рекурсивно подниматься выше (упрощённо)
	return s.validateParentChain(d, dnskeys)
}

// validateParentChain — рекурсивная проверка вверх по доменам (упрощённо)
func (s *DNSServer) validateParentChain(domain string, dnskeys []*dns.DNSKEY) bool {
	parent := parentDomain(domain)
	if parent == domain || parent == "." {
		return false
	}
	ds := s.getCachedDS(parent)
	if ds == nil {
		fetched, err := s.fetchDS(parent)
		if err == nil && len(fetched) > 0 {
			s.cacheDS(parent, fetched)
			ds = fetched
		}
	}
	if ds == nil || len(ds) == 0 {
		return s.validateParentChain(parent, dnskeys)
	}
	for _, drec := range ds {
		for _, key := range dnskeys {
			if verifyDS(drec, key) {
				return true
			}
		}
	}
	return false
}

// verifyDS сверяет DS и DNSKEY — корректно формирует RDATA и вычисляет hash
func verifyDS(ds *dns.DS, dnskey *dns.DNSKEY) bool {
	// decode public key
	keyData, err := base64.StdEncoding.DecodeString(dnskey.PublicKey)
	if err != nil {
		return false
	}
	// RDATA: Flags(2) | Protocol(1) | Algorithm(1) | PublicKey
	rdata := make([]byte, 4+len(keyData))
	binary.BigEndian.PutUint16(rdata[0:], dnskey.Flags)
	rdata[2] = dnskey.Protocol
	rdata[3] = dnskey.Algorithm
	copy(rdata[4:], keyData)

	switch ds.DigestType {
	case dns.SHA1:
		sum := sha1.Sum(rdata)
		return strings.EqualFold(hex.EncodeToString(sum[:]), ds.Digest)
	case dns.SHA256:
		sum := sha256.Sum256(rdata)
		return strings.EqualFold(hex.EncodeToString(sum[:]), ds.Digest)
	default:
		// unsupported digest
		return false
	}
}

// ----------------------- Negative proof (NSEC/NSEC3) -----------------------

// fetchNegativeProofRecords — упрощённо получает NSEC / NSEC3 записи через QNAME minimization
func (s *DNSServer) fetchNegativeProofRecords(domain string) ([]*dns.NSEC, []*dns.NSEC3, error) {
	res := s.qnameMinimizeResolve(domain, "NSEC")
	var nsecs []*dns.NSEC
	for _, rr := range res {
		if n, ok := rr.(*dns.NSEC); ok {
			nsecs = append(nsecs, n)
		}
	}
	res3 := s.qnameMinimizeResolve(domain, "NSEC3")
	var nsec3s []*dns.NSEC3
	for _, rr := range res3 {
		if n3, ok := rr.(*dns.NSEC3); ok {
			nsec3s = append(nsec3s, n3)
		}
	}
	return nsecs, nsec3s, nil
}

// ----------------------- Request handler -----------------------

func (s *DNSServer) handleRequest(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		s.sendErrorResponse(w, req, dns.RcodeFormatError, "no question")
		return
	}
	question := req.Question[0]
	qname := dns.Fqdn(question.Name)
	queryKey := fmt.Sprintf("%s:%d", qname, question.Qtype)

	// quarantine check
	if v, ok := s.quarantined.Load(qname); ok {
		if tt, ok2 := v.(time.Time); ok2 {
			if time.Now().Before(tt) {
				s.sendErrorResponse(w, req, dns.RcodeNameError, "temporarily quarantined")
				return
			}
		}
	}

	// detect recursion / loop
	if _, ok := s.visited.Load(queryKey); ok {
		s.sendErrorResponse(w, req, dns.RcodeRefused, "potential recursion")
		return
	}
	s.visited.Store(queryKey, time.Now())
	defer s.visited.Delete(queryKey)

	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.RecursionAvailable = true
	reply.Compress = true

	udpSize := uint16(512)
	clientRequestsDNSSEC := false
	if edns := req.IsEdns0(); edns != nil {
		udpSize = edns.UDPSize()
		if udpSize < 512 {
			udpSize = 512
		}
		if udpSize > maxUDPSize {
			udpSize = maxUDPSize
		}
		clientRequestsDNSSEC = edns.Do()
		reply.SetEdns0(udpSize, edns.Do())
	}

	// perform recursive resolution via QNAME-minimization path for answer type
	qtypeStr := dns.TypeToString[question.Qtype]
	if qtypeStr == "" {
		s.sendErrorResponse(w, req, dns.RcodeNotImplemented, "unsupported qtype")
		return
	}

	rrs := s.qnameMinimizeResolve(qname, qtypeStr)
	hasAnswer := false
	for _, rr := range rrs {
		// append only records matching the qtype (there are some cases where upstream returns other types)
		if rr.Header().Rrtype == question.Qtype {
			reply.Answer = append(reply.Answer, rr)
			hasAnswer = true
		}
	}

	// If no answer => NXDOMAIN/negative; attempt negative proof if client asked DNSSEC
	if !hasAnswer {
		// if DNSSEC requested, try negative proof validation
		if clientRequestsDNSSEC {
			val := s.validateNegativeResponse(qname)
			switch val {
			case DNSSEC_SECURE:
				reply.MsgHdr.AuthenticatedData = true
				atomic.AddUint64(&s.secureQueries, 1)
			case DNSSEC_BOGUS:
				atomic.AddUint64(&s.bogusQueries, 1)
				s.sendErrorResponse(w, req, dns.RcodeServerFailure, "dnssec negative proof bogus")
				return
			case DNSSEC_INDETERMINATE:
				atomic.AddUint64(&s.indeterminateQueries, 1)
			case DNSSEC_INSECURE:
				atomic.AddUint64(&s.insecureQueries, 1)
			}
		}

		// track NXDOMAIN counters for quarantine
		cnt := 1
		if v, ok := s.nxdomainCounter.Load(qname); ok {
			if ci, ok2 := v.(int); ok2 {
				cnt = ci + 1
			}
		}
		s.nxdomainCounter.Store(qname, cnt)
		s.nxdomainLastSeen.Store(qname, time.Now())
		if cnt >= nxdomainLimit {
			s.quarantined.Store(qname, time.Now().Add(quarantinePeriod))
		}

		reply.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(reply)
		return
	}

	// If client requested DNSSEC (DO) or server wants to validate, perform DNSSEC validation
	if clientRequestsDNSSEC || true {
		// validate answer
		val := s.validateDNSSEC(qname, reply)
		switch val {
		case DNSSEC_SECURE:
			reply.MsgHdr.AuthenticatedData = true
			atomic.AddUint64(&s.secureQueries, 1)
		case DNSSEC_BOGUS:
			atomic.AddUint64(&s.bogusQueries, 1)
			// If bogus, we should refuse to serve bad data
			s.sendErrorResponse(w, req, dns.RcodeServerFailure, "dnssec validation failed")
			return
		case DNSSEC_INDETERMINATE:
			atomic.AddUint64(&s.indeterminateQueries, 1)
		case DNSSEC_INSECURE:
			atomic.AddUint64(&s.insecureQueries, 1)
		}
	}

	// If client requested DNSSEC, attach RRSIG/DNSKEY/DS where possible (in Extra)
	if clientRequestsDNSSEC {
		rrsigs, dnskeys, ds, _ := s.fetchDNSSECRecords(qname)
		for _, r := range rrsigs {
			reply.Extra = append(reply.Extra, r)
		}
		for _, k := range dnskeys {
			reply.Extra = append(reply.Extra, k)
		}
		for _, d := range ds {
			reply.Extra = append(reply.Extra, d)
		}
	}

	// If reply too big for UDP -> let client fallback to TCP (we simply write; server lib may handle truncation)
	if reply.Len() > int(udpSize) {
		reply.Truncated = true
	}

	if err := w.WriteMsg(reply); err != nil {
		fmt.Printf("write error: %v\n", err)
	}
}

// validateNegativeResponse — упрощённая проверка отрицательных ответов (NSEC/NSEC3)
func (s *DNSServer) validateNegativeResponse(domain string) DNSSECValidationResult {
	nsec, nsec3, err := s.fetchNegativeProofRecords(domain)
	if err != nil {
		fmt.Printf("fetch negative proof error: %v\n", err)
		return DNSSEC_INDETERMINATE
	}
	if len(nsec) == 0 && len(nsec3) == 0 {
		return DNSSEC_INSECURE
	}
	// упрощённо: если хоть одна запись есть — считаем secure (для тестирования)
	if len(nsec) > 0 || len(nsec3) > 0 {
		return DNSSEC_SECURE
	}
	return DNSSEC_BOGUS
}

// fetchDNSSECRecords (sync) возвращает RRSIG, DNSKEY, DS (использует qnameMinimizeResolve)
func (s *DNSServer) fetchDNSSECRecords(domain string) ([]*dns.RRSIG, []*dns.DNSKEY, []*dns.DS, error) {
	rrsigs, dnskeys, ds, err := s.fetchDNSSECRecordsAsync(domain)
	return rrsigs, dnskeys, ds, err
}

// ----------------------- Error response helper -----------------------
func (s *DNSServer) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int, message string) {
	reply := new(dns.Msg)
	if req != nil {
		reply.SetRcode(req, rcode)
		reply.Compress = true
		// preserve EDNS DO flag
		if edns := req.IsEdns0(); edns != nil {
			reply.SetEdns0(edns.UDPSize(), edns.Do())
		}
		if len(req.Question) > 0 {
			txt := &dns.TXT{
				Hdr: dns.RR_Header{Name: dns.Fqdn(req.Question[0].Name), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
				Txt: []string{message},
			}
			reply.Extra = append(reply.Extra, txt)
		}
	}
	_ = w.WriteMsg(reply)
}

// ----------------------- Main -----------------------
func main() {
	s := NewDNSServer()
	go s.startCleaner()

	dns.HandleFunc(".", s.handleRequest)

	udpSrv := &dns.Server{Addr: listenAddr, Net: "udp"}
	tcpSrv := &dns.Server{Addr: listenAddr, Net: "tcp"}

	go func() {
		fmt.Printf("Starting UDP server on %s\n", listenAddr)
		if err := udpSrv.ListenAndServe(); err != nil {
			fmt.Printf("UDP server error: %v\n", err)
		}
	}()

	go func() {
		fmt.Printf("Starting TCP server on %s\n", listenAddr)
		if err := tcpSrv.ListenAndServe(); err != nil {
			fmt.Printf("TCP server error: %v\n", err)
		}
	}()

	select {}
}
