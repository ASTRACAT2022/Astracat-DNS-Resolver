package main

import (
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/domainr/dnsr"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
)

// DNSServer содержит все необходимые компоненты для DNS-сервера
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

	// Метрики
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

// DNSSECValidationResult представляет результат проверки DNSSEC
type DNSSECValidationResult int

const (
	DNSSEC_SECURE DNSSECValidationResult = iota
	DNSSEC_INSECURE
	DNSSEC_BOGUS
	DNSSEC_INDETERMINATE
)

var base32HexNoPad = base32.HexEncoding.WithPadding(base32.NoPadding)

// NewDNSServer создает и инициализирует новый DNS-сервер
func NewDNSServer() *DNSServer {
	server := &DNSServer{
		resolver:      dnsr.NewResolver(),
		dnssecEnabled: true,
	}
	server.initializeTrustAnchor()
	return server
}

// initializeTrustAnchor инициализирует доверенный корень
func (s *DNSServer) initializeTrustAnchor() {
	// Root KSK-2017 (RFC 8624)
	keyStr := ". IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5ZRzF9YWcJnJzRc5Diz20y+O3j2YiD6ZGyXaK0r1W/0WZi8c9I0HPObYJw8FXQzG00kHvU1OqqCtKkRBOhB4wR5KJ4QkhzN5ZU5lFsNhqVCKVCYyUMxMEJlJQZlNq6q+aIzHVMZQnR4ggr3H8H9U9F92F6VK7S9ZQ1Y="

	rr, err := dns.NewRR(keyStr)
	if err != nil {
		fmt.Printf("Не удалось разобрать доверенную точку: %v\n", err)
		return
	}

	if dnskey, ok := rr.(*dns.DNSKEY); ok {
		s.trustAnchor = dnskey
		fmt.Println("Доверенная точка успешно инициализирована")
	}
}

// startCleaner запускает фоновую очистку кэшей
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

		// Очистка visited
		s.visited.Range(func(key, value interface{}) bool {
			if ts, ok := value.(time.Time); ok {
				if now.Sub(ts) > visitedTTL {
					s.visited.Delete(key)
					visitedCount++
				}
			}
			return true
		})

		// Очистка nxdomainCounter
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

		// Освобождение доменов из карантина
		s.quarantined.Range(func(key, value interface{}) bool {
			if releaseTime, ok := value.(time.Time); ok {
				if now.After(releaseTime) {
					s.quarantined.Delete(key)
					quarantineCount++
				}
			}
			return true
		})

		// Очистка кэша ключей
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

		// Очистка кэша DS
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

		// Очистка кэша RRSIG
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

		fmt.Printf("Очищено %d старых записей из visited.\n", visitedCount)
		fmt.Printf("Сброшено %d счетчиков NXDOMAIN из-за неактивности.\n", nxdomainCount)
		fmt.Printf("Освобождено %d доменов из карантина.\n", quarantineCount)
		fmt.Printf("Очищено %d истёкших ключей из кэша.\n", keyCacheCount)
		fmt.Printf("Очищено %d истёкших DS-записей из кэша.\n", dsCacheCount)
		fmt.Printf("Очищено %d истёкших RRSIG-записей из кэша.\n", rrsigCacheCount)

		// Вывод метрик
		fmt.Printf("Метрики - Secure: %d, Insecure: %d, Bogus: %d, Indeterminate: %d\n",
			atomic.LoadUint64(&s.secureQueries),
			atomic.LoadUint64(&s.insecureQueries),
			atomic.LoadUint64(&s.bogusQueries),
			atomic.LoadUint64(&s.indeterminateQueries))
		fmt.Printf("Кэш - Hits: %d, Misses: %d\n",
			atomic.LoadUint64(&s.cacheHits),
			atomic.LoadUint64(&s.cacheMisses))
	}
}

// handleRequest обрабатывает входящие DNS-запросы
func (s *DNSServer) handleRequest(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		s.sendErrorResponse(w, req, dns.RcodeFormatError, "Нет вопросов в запросе")
		return
	}

	question := req.Question[0]
	queryKey := fmt.Sprintf("%s:%d", strings.ToLower(dns.CanonicalName(question.Name)), question.Qtype)

	// Проверка, не находится ли домен в карантине
	if releaseTime, isQuarantined := s.quarantined.Load(strings.ToLower(dns.CanonicalName(question.Name))); isQuarantined {
		if releaseTimeT, ok := releaseTime.(time.Time); ok {
			if time.Now().Before(releaseTimeT) {
				s.sendErrorResponse(w, req, dns.RcodeNameError, "Домен временно в карантине")
				return
			}
		}
	}

	// Проверка возможного рекурсивного запроса
	if _, exists := s.visited.Load(queryKey); exists {
		s.sendErrorResponse(w, req, dns.RcodeRefused, "Обнаружен потенциальный циклический запрос")
		return
	}

	s.visited.Store(queryKey, time.Now())
	defer s.visited.Delete(queryKey)

	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Compress = true
	reply.RecursionAvailable = true

	// Обработка EDNS0 и флага DNSSEC
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
		s.sendErrorResponse(w, req, dns.RcodeNotImplemented, "Неподдерживаемый QTYPE")
		return
	}

	fmt.Printf("=== Разрешение %s %s (DNSSEC: %v) ===\n", question.Name, qtypeStr, clientRequestsDNSSEC)
	
	// Выполнение рекурсивного разрешения с QNAME минимизацией
	results := s.resolver.Resolve(question.Name, qtypeStr)
	fmt.Printf("Результаты от резолвера для %s %s:\n", question.Name, qtypeStr)
	for i, res := range results {
		fmt.Printf("  [%d] %s\n", i, res.String())
	}
	
	var hasValidAnswer bool

	for _, res := range results {
		if res.String() != "" {
			rr, err := dns.NewRR(res.String())
			if err != nil {
				fmt.Printf("Не удалось разобрать RR '%s': %v\n", res.String(), err)
				continue
			}
			reply.Answer = append(reply.Answer, rr)
			hasValidAnswer = true
		}
	}

	// Отслеживание результата проверки DNSSEC
	dnssecValidationResult := DNSSEC_INDETERMINATE // По умолчанию
	isDNSSECValidationAttempted := false

	// Обработка NXDOMAIN
	if !hasValidAnswer {
		if clientRequestsDNSSEC {
			isDNSSECValidationAttempted = true
			validationResult := s.validateNegativeResponse(question.Name, reply)
			dnssecValidationResult = validationResult
			switch validationResult {
			case DNSSEC_SECURE:
				atomic.AddUint64(&s.secureQueries, 1)
				fmt.Printf("Успешная проверка DNSSEC для отрицательного ответа %s\n", question.Name)
			case DNSSEC_BOGUS:
				s.sendErrorResponse(w, req, dns.RcodeServerFailure, "Проверка DNSSEC провалилась для отрицательного ответа")
				atomic.AddUint64(&s.bogusQueries, 1)
				return
			case DNSSEC_INDETERMINATE:
				fmt.Printf("Недостаточно информации для проверки DNSSEC для отрицательного ответа %s\n", question.Name)
				atomic.AddUint64(&s.indeterminateQueries, 1)
			case DNSSEC_INSECURE:
				fmt.Printf("Домен не защищен (без DNSSEC) для отрицательного ответа %s\n", question.Name)
				atomic.AddUint64(&s.insecureQueries, 1)
			}
		}

		// Увеличение счетчика NXDOMAIN
		counter, _ := s.nxdomainCounter.LoadOrStore(strings.ToLower(dns.CanonicalName(question.Name)), 0)
		count := counter.(int) + 1
		s.nxdomainCounter.Store(strings.ToLower(dns.CanonicalName(question.Name)), count)
		s.nxdomainLastSeen.Store(strings.ToLower(dns.CanonicalName(question.Name)), time.Now())

		if count >= nxdomainLimit {
			fmt.Printf("Достигнут лимит NXDOMAIN для '%s'. Перевод в карантин на 30 секунд.\n", question.Name)
			s.quarantined.Store(strings.ToLower(dns.CanonicalName(question.Name)), time.Now().Add(quarantinePeriod))
		}

		reply.SetRcode(req, dns.RcodeNameError)
		// Применение результата DNSSEC перед отправкой
		if isDNSSECValidationAttempted && dnssecValidationResult == DNSSEC_SECURE {
			reply.MsgHdr.AuthenticatedData = true
		}
		if err := w.WriteMsg(reply); err != nil {
			fmt.Printf("Ошибка записи ответа: %v\n", err)
		}
		return
	}

	// Обработка проверки DNSSEC
	if s.dnssecEnabled && clientRequestsDNSSEC && hasValidAnswer {
		isDNSSECValidationAttempted = true
		// Проверка наличия RRSIG в ответе
		hasRRSIGs := false
		for _, rr := range reply.Answer {
			if _, ok := rr.(*dns.RRSIG); ok {
				hasRRSIGs = true
				break
			}
		}
		
		fmt.Printf("Проверка наличия RRSIG в ответе: hasRRSIGs=%v\n", hasRRSIGs)
		if hasRRSIGs {
			validationResult := s.validateDNSSEC(question.Name, reply)
			dnssecValidationResult = validationResult
			switch validationResult {
			case DNSSEC_SECURE:
				atomic.AddUint64(&s.secureQueries, 1)
				fmt.Printf("Успешная проверка DNSSEC для %s\n", question.Name)
			case DNSSEC_BOGUS:
				s.sendErrorResponse(w, req, dns.RcodeServerFailure, "Проверка DNSSEC провалилась")
				atomic.AddUint64(&s.bogusQueries, 1)
				return
			case DNSSEC_INDETERMINATE:
				fmt.Printf("Недостаточно информации для проверки DNSSEC для %s\n", question.Name)
				atomic.AddUint64(&s.indeterminateQueries, 1)
			case DNSSEC_INSECURE:
				fmt.Printf("Домен не защищен (без DNSSEC) для %s\n", question.Name)
				atomic.AddUint64(&s.insecureQueries, 1)
			}
		} else {
			fmt.Printf("RRSIG не найдены для %s, попытка получения через резолвер и авторитетные серверы\n", question.Name)
			// сначала резолвер
			rrsigResults := s.qnameMinimizeResolve(question.Name, "RRSIG")
			for _, r := range rrsigResults {
				if rr, err := dns.NewRR(r); err == nil {
					if rrsig, ok := rr.(*dns.RRSIG); ok {
						if rrsig.TypeCovered == question.Qtype {
							reply.Answer = append(reply.Answer, rrsig)
							hasRRSIGs = true
							fmt.Printf("Добавлен RRSIG из резолвера: %s\n", rrsig.String())
						}
					}
				}
			}
			// затем авторитетные серверы, если всё ещё нет
			if !hasRRSIGs {
				rrsetFromAuth, rrsigsFromAuth := s.fetchFromAuthoritative(question.Name, question.Qtype)
				for _, rrsig := range rrsigsFromAuth {
					if rrsig.TypeCovered == question.Qtype {
						reply.Answer = append(reply.Answer, rrsig)
						hasRRSIGs = true
						fmt.Printf("Добавлен RRSIG из авторитетного сервера: %s\n", rrsig.String())
					}
				}
				_ = rrsetFromAuth
			}
			if hasRRSIGs {
				validationResult := s.validateDNSSEC(question.Name, reply)
				dnssecValidationResult = validationResult
				switch validationResult {
				case DNSSEC_SECURE:
					atomic.AddUint64(&s.secureQueries, 1)
					fmt.Printf("Успешная проверка DNSSEC для %s\n", question.Name)
				case DNSSEC_BOGUS:
					s.sendErrorResponse(w, req, dns.RcodeServerFailure, "Проверка DNSSEC провалилась")
					atomic.AddUint64(&s.bogusQueries, 1)
					return
				case DNSSEC_INDETERMINATE:
					fmt.Printf("Недостаточно информации для проверки DNSSEC для %s\n", question.Name)
					atomic.AddUint64(&s.indeterminateQueries, 1)
				case DNSSEC_INSECURE:
					fmt.Printf("Домен не защищен (без DNSSEC) для %s\n", question.Name)
					atomic.AddUint64(&s.insecureQueries, 1)
				}
			} else {
				fmt.Printf("RRSIG не доступны для %s после дополнительного поиска. Попытка получить DNSKEY/DS для диагностики.\n", question.Name)
				rrs, keys, dsRecs, err := s.fetchDNSSECRecordsAsync(question.Name)
				if err != nil {
					fmt.Printf("Ошибка получения DNSSEC записей для диагностики: %v\n", err)
					atomic.AddUint64(&s.indeterminateQueries, 1)
					dnssecValidationResult = DNSSEC_INDETERMINATE
				} else {
					if len(rrs) == 0 && len(keys) == 0 && len(dsRecs) == 0 {
						fmt.Printf("DNSSEC записи не найдены для %s — обработка как INSECURE\n", question.Name)
						atomic.AddUint64(&s.insecureQueries, 1)
						dnssecValidationResult = DNSSEC_INSECURE
					} else {
						fmt.Printf("DNSSEC артефакты присутствуют, но нет подходящих RRSIG для %s — обработка как INDETERMINATE\n", question.Name)
						atomic.AddUint64(&s.indeterminateQueries, 1)
						dnssecValidationResult = DNSSEC_INDETERMINATE
					}
				}
			}
		}
	}

	// Применение результата DNSSEC перед отправкой
	if isDNSSECValidationAttempted && dnssecValidationResult == DNSSEC_SECURE {
		reply.MsgHdr.AuthenticatedData = true
	}
	
	if err := w.WriteMsg(reply); err != nil {
		fmt.Printf("Ошибка записи ответа: %v\n", err)
	}
}

// validateDNSSEC проверяет DNSSEC-подпись ответа
func (s *DNSServer) validateDNSSEC(qname string, reply *dns.Msg) DNSSECValidationResult {
	fmt.Printf("Начало проверки DNSSEC для %s\n", qname)
	
	// Извлечение RRSIG и RRSET
	var rrsigs []*dns.RRSIG
	var rrset []dns.RR
	
	for _, rr := range reply.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			rrsigs = append(rrsigs, rrsig)
		} else {
			rrset = append(rrset, rr)
		}
	}
	
	if len(rrsigs) == 0 {
		fmt.Printf("Нет RRSIG записей для проверки %s\n", qname)
		return DNSSEC_INDETERMINATE
	}
	
	if len(rrset) == 0 {
		fmt.Printf("Нет RRSET для проверки %s\n", qname)
		return DNSSEC_INDETERMINATE
	}
	
	// Проверка каждой подписи
	for _, rrsig := range rrsigs {
		fmt.Printf("Проверка RRSIG: %s\n", rrsig.String())
		
		// Получение DNSKEY
		dnskey, err := s.getDNSKEY(rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
		if err != nil {
			fmt.Printf("Не удалось получить DNSKEY для %s: %v\n", rrsig.SignerName, err)
			return DNSSEC_INDETERMINATE
		}
		
		if dnskey == nil {
			fmt.Printf("DNSKEY не найден для %s\n", rrsig.SignerName)
			return DNSSEC_INDETERMINATE
		}
		
		// Проверка подписи
		err = rrsig.Verify(dnskey, rrset)
		if err != nil {
			fmt.Printf("Проверка подписи провалилась для %s: %v\n", qname, err)
			return DNSSEC_BOGUS
		}
		
		fmt.Printf("Подпись проверена успешно для %s\n", qname)
	}
	
	return DNSSEC_SECURE
}

// validateNegativeResponse проверяет DNSSEC для отрицательных ответов
func (s *DNSServer) validateNegativeResponse(qname string, reply *dns.Msg) DNSSECValidationResult {
	fmt.Printf("Проверка DNSSEC для отрицательного ответа: %s\n", qname)
	
	// Поиск NSEC/NSEC3 и RRSIG записей
	var nsecRecords []dns.RR
	var rrsigs []*dns.RRSIG
	
	for _, rr := range reply.Ns {
		switch rr.(type) {
		case *dns.NSEC:
			nsecRecords = append(nsecRecords, rr)
		case *dns.NSEC3:
			nsecRecords = append(nsecRecords, rr)
		case *dns.RRSIG:
			if rrsig, ok := rr.(*dns.RRSIG); ok {
				if rrsig.TypeCovered == dns.TypeNSEC || rrsig.TypeCovered == dns.TypeNSEC3 {
					rrsigs = append(rrsigs, rrsig)
				}
			}
		}
	}
	
	if len(nsecRecords) == 0 || len(rrsigs) == 0 {
		fmt.Printf("Нет NSEC/NSEC3 или RRSIG записей для проверки отрицательного ответа %s\n", qname)
		return DNSSEC_INDETERMINATE
	}
	
	// Проверка подписей
	for _, rrsig := range rrsigs {
		dnskey, err := s.getDNSKEY(rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
		if err != nil || dnskey == nil {
			fmt.Printf("Не удалось получить DNSKEY для отрицательного ответа %s: %v\n", qname, err)
			return DNSSEC_INDETERMINATE
		}
		
		err = rrsig.Verify(dnskey, nsecRecords)
		if err != nil {
			fmt.Printf("Проверка подписи отрицательного ответа провалилась для %s: %v\n", qname, err)
			return DNSSEC_BOGUS
		}
	}
	
	return DNSSEC_SECURE
}

// getDNSKEY получает DNSKEY по имени, тегу и алгоритму
func (s *DNSServer) getDNSKEY(signerName string, keyTag uint16, algorithm uint8) (*dns.DNSKEY, error) {
	cacheKey := fmt.Sprintf("%s:%d:%d", signerName, keyTag, algorithm)
	
	// Проверка кэша
	if cached, ok := s.keyCache.Load(cacheKey); ok {
		if cachedTime, ok := s.keyCacheTime.Load(cacheKey); ok {
			if time.Since(cachedTime.(time.Time)) < keyCacheTTL {
				atomic.AddUint64(&s.cacheHits, 1)
				return cached.(*dns.DNSKEY), nil
			}
		}
	}
	
	atomic.AddUint64(&s.cacheMisses, 1)
	
	// Получение через резолвер
	results := s.resolver.Resolve(signerName, "DNSKEY")
	for _, res := range results {
		if rr, err := dns.NewRR(res.String()); err == nil {
			if dnskey, ok := rr.(*dns.DNSKEY); ok {
				if dnskey.KeyTag() == keyTag && dnskey.Algorithm == algorithm {
					// Кэширование
					s.keyCache.Store(cacheKey, dnskey)
					s.keyCacheTime.Store(cacheKey, time.Now())
					return dnskey, nil
				}
			}
		}
	}
	
	// Если не найдено через резолвер, попробуем получить через авторитетные серверы
	dnskey, err := s.fetchDNSKEYFromAuthoritative(signerName, keyTag, algorithm)
	if err == nil && dnskey != nil {
		s.keyCache.Store(cacheKey, dnskey)
		s.keyCacheTime.Store(cacheKey, time.Now())
		return dnskey, nil
	}
	
	return nil, fmt.Errorf("DNSKEY не найден для %s, tag=%d, alg=%d", signerName, keyTag, algorithm)
}

// fetchDNSKEYFromAuthoritative получает DNSKEY напрямую от авторитетных серверов
func (s *DNSServer) fetchDNSKEYFromAuthoritative(signerName string, keyTag uint16, algorithm uint8) (*dns.DNSKEY, error) {
	// Получение NS записей
	nsResults := s.qnameMinimizeResolve(signerName, "NS")
	if len(nsResults) == 0 {
		return nil, fmt.Errorf("NS записи не найдены для %s", signerName)
	}
	
	// Получение A/AAAA записей для NS
	var nsIPs []string
	for _, nsRes := range nsResults {
		if rr, err := dns.NewRR(nsRes); err == nil {
			if ns, ok := rr.(*dns.NS); ok {
				aResults := s.qnameMinimizeResolve(ns.Ns, "A")
				for _, aRes := range aResults {
					if aRR, err := dns.NewRR(aRes); err == nil {
						if a, ok := aRR.(*dns.A); ok {
							nsIPs = append(nsIPs, a.A.String())
						}
					}
				}
				aaaaResults := s.qnameMinimizeResolve(ns.Ns, "AAAA")
				for _, aaaaRes := range aaaaResults {
					if aaaaRR, err := dns.NewRR(aaaaRes); err == nil {
						if aaaa, ok := aaaaRR.(*dns.AAAA); ok {
							nsIPs = append(nsIPs, aaaa.AAAA.String())
						}
					}
				}
			}
		}
	}
	
	if len(nsIPs) == 0 {
		return nil, fmt.Errorf("IP адреса NS серверов не найдены для %s", signerName)
	}
	
	// Запрос DNSKEY у первого доступного NS сервера
	c := &dns.Client{Timeout: 5 * time.Second}
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(signerName), dns.TypeDNSKEY)
	
	for _, nsIP := range nsIPs {
		addr := net.JoinHostPort(nsIP, "53")
		resp, _, err := c.Exchange(msg, addr)
		if err != nil {
			continue
		}
		
		for _, rr := range resp.Answer {
			if dnskey, ok := rr.(*dns.DNSKEY); ok {
				if dnskey.KeyTag() == keyTag && dnskey.Algorithm == algorithm {
					return dnskey, nil
				}
			}
		}
	}
	
	return nil, fmt.Errorf("не удалось получить DNSKEY от авторитетных серверов")
}

// qnameMinimizeResolve выполняет рекурсивное разрешение с минимизацией QNAME
func (s *DNSServer) qnameMinimizeResolve(qname, qtype string) []string {
	labels := dns.SplitDomainName(qname)
	var results []string
	
	// Начинаем с корня и двигаемся вниз
	for i := len(labels); i >= 0; i-- {
		var currentName string
		if i == len(labels) {
			currentName = "."
		} else {
			currentName = strings.Join(labels[i:], ".") + "."
		}
		
		res := s.resolver.Resolve(currentName, "NS")
		if len(res) > 0 {
			// Найдены NS записи, теперь запросим нужный тип
			if i == 0 {
				// Это целевой домен
				targetResults := s.resolver.Resolve(qname, qtype)
				for _, tr := range targetResults {
					results = append(results, tr.String())
				}
				break
			}
		}
	}
	
	return results
}

// fetchFromAuthoritative получает записи напрямую от авторитетных серверов
func (s *DNSServer) fetchFromAuthoritative(qname string, qtype uint16) ([]dns.RR, []*dns.RRSIG) {
	var rrset []dns.RR
	var rrsigs []*dns.RRSIG
	
	// Получение NS записей через минимизацию QNAME
	labels := dns.SplitDomainName(qname)
	
	for i := 0; i <= len(labels); i++ {
		var zone string
		if i == len(labels) {
			zone = "."
		} else {
			zone = strings.Join(labels[i:], ".") + "."
		}
		
		nsResults := s.resolver.Resolve(zone, "NS")
		if len(nsResults) > 0 {
			// Найдены NS серверы для этой зоны
			for _, nsRes := range nsResults {
				if rr, err := dns.NewRR(nsRes.String()); err == nil {
					if _, ok := rr.(*dns.NS); ok {
						// Получаем IP адреса NS серверов
						nsName := rr.Header().Name
						aResults := s.resolver.Resolve(nsName, "A")
						for _, aRes := range aResults {
							if aRR, err := dns.NewRR(aRes.String()); err == nil {
								if a, ok := aRR.(*dns.A); ok {
									// Запрашиваем записи у NS сервера
									c := &dns.Client{Timeout: 5 * time.Second}
									msg := &dns.Msg{}
									msg.SetQuestion(dns.Fqdn(qname), qtype)
									msg.SetEdns0(4096, true) // Запрашиваем DNSSEC
									
									addr := net.JoinHostPort(a.A.String(), "53")
									resp, _, err := c.Exchange(msg, addr)
									if err == nil {
										for _, answer := range resp.Answer {
											if answer.Header().Rrtype == qtype {
												rrset = append(rrset, answer)
											} else if answer.Header().Rrtype == dns.TypeRRSIG {
												if rrsig, ok := answer.(*dns.RRSIG); ok {
													if rrsig.TypeCovered == qtype {
														rrsigs = append(rrsigs, rrsig)
													}
												}
											}
										}
										return rrset, rrsigs
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	return rrset, rrsigs
}

// fetchDNSSECRecordsAsync асинхронно получает DNSSEC записи
func (s *DNSServer) fetchDNSSECRecordsAsync(qname string) ([]dns.RR, []*dns.DNSKEY, []*dns.DS, error) {
	var rrs []dns.RR
	var keys []*dns.DNSKEY
	var dsRecords []*dns.DS
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Получение RRSIG
	wg.Add(1)
	go func() {
		defer wg.Done()
		results := s.resolver.Resolve(qname, "RRSIG")
		mu.Lock()
		defer mu.Unlock()
		for _, res := range results {
			if rr, err := dns.NewRR(res.String()); err == nil {
				rrs = append(rrs, rr)
			}
		}
	}()
	
	// Получение DNSKEY
	wg.Add(1)
	go func() {
		defer wg.Done()
		results := s.resolver.Resolve(qname, "DNSKEY")
		mu.Lock()
		defer mu.Unlock()
		for _, res := range results {
			if rr, err := dns.NewRR(res.String()); err == nil {
				if key, ok := rr.(*dns.DNSKEY); ok {
					keys = append(keys, key)
				}
			}
		}
	}()
	
	// Получение DS
	wg.Add(1)
	go func() {
		defer wg.Done()
		results := s.resolver.Resolve(qname, "DS")
		mu.Lock()
		defer mu.Unlock()
		for _, res := range results {
			if rr, err := dns.NewRR(res.String()); err == nil {
				if ds, ok := rr.(*dns.DS); ok {
					dsRecords = append(dsRecords, ds)
				}
			}
		}
	}()
	
	wg.Wait()
	
	if len(rrs) == 0 && len(keys) == 0 && len(dsRecords) == 0 {
		return rrs, keys, dsRecords, fmt.Errorf("DNSSEC записи не найдены")
	}
	
	return rrs, keys, dsRecords, nil
}

// sendErrorResponse отправляет ошибочный ответ
func (s *DNSServer) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int, errMsg string) {
	fmt.Printf("Ошибка: %s\n", errMsg)
	reply := new(dns.Msg)
	reply.SetRcode(req, rcode)
	w.WriteMsg(reply)
}

// Start запускает DNS-сервер
func (s *DNSServer) Start(addr string) error {
	// Запуск очистки кэша в отдельной горутине
	go s.startCleaner()
	
	// Регистрация обработчика
	dns.HandleFunc(".", s.handleRequest)
	
	// Создание сервера
	server := &dns.Server{
		Addr: addr,
		Net:  "udp",
	}
	
	fmt.Printf("DNS-сервер запущен на %s\n", addr)
	return server.ListenAndServe()
}

func main() {
	server := NewDNSServer()
	if err := server.Start(":53"); err != nil {
		fmt.Printf("Ошибка запуска сервера: %v\n", err)
	}
}
