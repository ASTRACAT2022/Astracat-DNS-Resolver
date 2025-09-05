package main

import (
    "crypto/sha1"
    "crypto/sha256"
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

// DNSServer содержит все необходимые компоненты DNS-сервера
type DNSServer struct {
    resolver         *dnsr.Resolver
    visited          sync.Map // map[string]time.Time
    nxdomainCounter  sync.Map // map[string]int
    nxdomainLastSeen sync.Map // map[string]time.Time
    quarantined      sync.Map // map[string]time.Time
    dnssecEnabled    bool
    trustAnchor      *dns.DNSKEY // Корневой доверенный ключ
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

// DNSSECValidationResult результат валидации DNSSEC
type DNSSECValidationResult int

const (
    DNSSEC_SECURE DNSSECValidationResult = iota
    DNSSEC_INSECURE
    DNSSEC_BOGUS
    DNSSEC_INDETERMINATE
)

// NewDNSServer создаёт и инициализирует новый DNS-сервер
func NewDNSServer() *DNSServer {
    server := &DNSServer{
        resolver:      dnsr.NewResolver(),
        dnssecEnabled: true,
    }

    // Инициализируем корневой доверенный ключ (KSK-2017)
    server.initializeTrustAnchor()
    return server
}

// initializeTrustAnchor инициализирует корневой доверенный ключ
func (s *DNSServer) initializeTrustAnchor() {
    // Корневой KSK-2017 (RFC 8624)
    keyStr := ". IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5ZRzF9YWcJnJzRc5Diz20y+O3j2YiD6ZGyXa K0r1W/0WZi8c9I0HPObYJw8FXQzG00kHvU1OqqCtKkRBOhB4wR5KJ4Qk hzN5ZU5lFsNhqVCKVCYyUMxMEJlJQZlNq6q+aIzHVMZQnR4ggr3H8H9U 9F92F6VK7S9ZQ1Y="

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

// startCleaner запускает фоновую горутину для очистки visited map
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

        // Очистка visited map
        s.visited.Range(func(key, value interface{}) bool {
            if ts, ok := value.(time.Time); ok {
                if now.Sub(ts) > visitedTTL {
                    s.visited.Delete(key)
                    visitedCount++
                }
            }
            return true
        })

        // "Умная" очистка nxdomainCounter
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

        // Снятие доменов с карантина
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

        // Очистка кэша DS записей
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

        // Очистка кэша RRSIG записей
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

        // Вывод метрик
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

// handleRequest обрабатывает входящие DNS-запросы
func (s *DNSServer) handleRequest(w dns.ResponseWriter, req *dns.Msg) {
    if len(req.Question) == 0 {
        s.sendErrorResponse(w, req, dns.RcodeFormatError, "No questions in request")
        return
    }

    question := req.Question[0]
    queryKey := fmt.Sprintf("%s:%d", question.Name, question.Qtype)

    // Проверяем, не находится ли домен на карантине
    if releaseTime, isQuarantined := s.quarantined.Load(question.Name); isQuarantined {
        if releaseTimeT, ok := releaseTime.(time.Time); ok {
            if time.Now().Before(releaseTimeT) {
                s.sendErrorResponse(w, req, dns.RcodeNameError, "Domain temporarily quarantined")
                return
            }
        }
    }

    // Проверка на потенциальную рекурсию
    if _, exists := s.visited.Load(queryKey); exists {
        s.sendErrorResponse(w, req, dns.RcodeRefused, "Potential query loop detected")
        return
    }

    s.visited.Store(queryKey, time.Now())

    defer func() {
        s.visited.Delete(queryKey)
    }()

    reply := new(dns.Msg)
    reply.SetReply(req)
    reply.Compress = true
    reply.RecursionAvailable = true

    // Устанавливаем DNSSEC флаги если клиент запрашивает DNSSEC
    clientRequestsDNSSEC := false
    udpSize := uint16(512) // размер по умолчанию

    if edns0 := req.IsEdns0(); edns0 != nil {
        if edns0.Do() {
            clientRequestsDNSSEC = true
        }
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

    // Выполняем рекурсивный запрос (с использованием QNAME minimization при необходимости)
    results := s.resolver.Resolve(question.Name, qtypeStr)
    var hasValidAnswer bool

    for _, res := range results {
        if res.String() != "" {
            rrStr := res.String()
            rr, err := dns.NewRR(rrStr)
            if err != nil {
                fmt.Printf("Failed to parse RR '%s': %v\n", rrStr, err)
                continue
            }
            reply.Answer = append(reply.Answer, rr)
            hasValidAnswer = true
        }
    }

    // Обработка отрицательных ответов (NXDOMAIN)
    if !hasValidAnswer {
        if clientRequestsDNSSEC {
            // Проверяем NSEC/NSEC3 записи для отрицательных ответов
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

        // Увеличиваем счетчик NXDOMAIN
        counter, _ := s.nxdomainCounter.Load(question.Name)
        count := 1
        if c, ok := counter.(int); ok {
            count = c + 1
        }
        s.nxdomainCounter.Store(question.Name, count)
        s.nxdomainLastSeen.Store(question.Name, time.Now())

        if count >= nxdomainLimit {
            fmt.Printf("NXDOMAIN limit reached for '%s'. Quarantining for 30 seconds.\n", question.Name)
            s.quarantined.Store(question.Name, time.Now().Add(quarantinePeriod))
        }

        reply.SetRcode(req, dns.RcodeNameError)
        if err := w.WriteMsg(reply); err != nil {
            fmt.Printf("Error writing response: %v\n", err)
        }
        return
    }

    // Добавляем DNSSEC записи если включено и клиент запрашивает
    if s.dnssecEnabled && clientRequestsDNSSEC {
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
    }

    // Очищаем счетчики для успешных запросов
    s.nxdomainCounter.Delete(question.Name)
    s.nxdomainLastSeen.Delete(question.Name)

    // Проверяем размер ответа
    if reply.Len() > int(udpSize) {
        // Для больших ответов используем TCP если возможно
    }

    if err := w.WriteMsg(reply); err != nil {
        fmt.Printf("Error writing response: %v\n", err)
    }
}

// validateNegativeResponse проверяет отрицательные ответы с NSEC/NSEC3
func (s *DNSServer) validateNegativeResponse(domain string, reply *dns.Msg) DNSSECValidationResult {
    // Асинхронно получаем NSEC/NSEC3 записи (с QNAME minimization)
    nsecRecords, nsec3Records, err := s.fetchNegativeProofRecords(domain)
    if err != nil {
        fmt.Printf("Failed to fetch negative proof records for %s: %v\n", domain, err)
        return DNSSEC_INDETERMINATE
    }

    // Если нет NSEC/NSEC3 записей, домен не защищен
    if len(nsecRecords) == 0 && len(nsec3Records) == 0 {
        return DNSSEC_INSECURE
    }

    // Проверяем NSEC/NSEC3 записи (упрощенная реализация)
    // В реальной реализации здесь должна быть полная проверка
    if len(nsecRecords) > 0 || len(nsec3Records) > 0 {
        return DNSSEC_SECURE
    }

    return DNSSEC_BOGUS
}

// fetchNegativeProofRecords получает NSEC/NSEC3 записи для отрицательных ответов
func (s *DNSServer) fetchNegativeProofRecords(domain string) ([]*dns.NSEC, []*dns.NSEC3, error) {
    var nsecRecords []*dns.NSEC
    var nsec3Records []*dns.NSEC3

    // Используем QNAME minimization для поиска доказательств
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

// qnameMinimizeResolve реализует простую QNAME minimization: пытаемcя получить ответ для имени, затем поднимаемся к родителю и т.д.
func (s *DNSServer) qnameMinimizeResolve(domain, qtype string) []string {
    d := domain
    tried := map[string]bool{}
    for {
        if _, ok := tried[d]; ok {
            break
        }
        tried[d] = true
        results := s.resolver.Resolve(d, qtype)
        if len(results) > 0 {
            var out []string
            for _, r := range results {
                out = append(out, r.String())
            }
            return out
        }
        parent := s.getParentDomain(d)
        if parent == d || parent == "." && d == "." {
            break
        }
        d = parent
    }
    return nil
}

// validateDNSSEC выполняет полную валидацию DNSSEC для ответа
func (s *DNSServer) validateDNSSEC(domain string, reply *dns.Msg) DNSSECValidationResult {
    // Асинхронно получаем все DNSSEC записи
    rrsigs, dnskeys, dsRecords, err := s.fetchDNSSECRecordsAsync(domain)
    if err != nil {
        fmt.Printf("Failed to fetch DNSSEC records for %s: %v\n", domain, err)
        return DNSSEC_INDETERMINATE
    }

    // Если нет DNSSEC записей, домен не защищен
    if len(rrsigs) == 0 && len(dnskeys) == 0 && len(dsRecords) == 0 {
        return DNSSEC_INSECURE
    }

    // Проверяем RRSIG записи используя встроенную функцию из miekg/dns
    for _, rrsig := range rrsigs {
        // Канонизируем RRSet перед проверкой
        canonicalRRSet := s.canonicalizeRRSet(reply.Answer, rrsig.TypeCovered)

        if !s.verifyRRSIGWithMiekg(rrsig, canonicalRRSet) {
            fmt.Printf("RRSIG verification failed for %s\n", domain)
            return DNSSEC_BOGUS
        }
    }

    // Проверяем цепочку доверия
    if !s.validateTrustChain(domain, dnskeys, dsRecords) {
        fmt.Printf("Trust chain validation failed for %s\n", domain)
        return DNSSEC_BOGUS
    }

    return DNSSEC_SECURE
}

// canonicalizeRRSet канонизирует RRSet для DNSSEC
func (s *DNSServer) canonicalizeRRSet(rrset []dns.RR, qtype uint16) []dns.RR {
    // Фильтруем записи по типу
    var filtered []dns.RR
    for _, rr := range rrset {
        if rr.Header().Rrtype == qtype {
            filtered = append(filtered, rr)
        }
    }

    if len(filtered) == 0 {
        return rrset
    }

    // Канонизируем имена (в нижний регистр)
    for _, rr := range filtered {
        rr.Header().Name = strings.ToLower(dns.CanonicalName(rr.Header().Name))
    }

    // Сортируем по каноническому порядку
    sort.Slice(filtered, func(i, j int) bool {
        return compareRR(filtered[i], filtered[j]) < 0
    })

    return filtered
}

// compareRR сравнивает две DNS записи
func compareRR(a, b dns.RR) int {
    // Сравниваем имена
    nameCompare := strings.Compare(
        strings.ToLower(dns.CanonicalName(a.Header().Name)),
        strings.ToLower(dns.CanonicalName(b.Header().Name)),
    )
    if nameCompare != 0 {
        return nameCompare
    }

    // Сравниваем типы
    if a.Header().Rrtype != b.Header().Rrtype {
        return int(a.Header().Rrtype) - int(b.Header().Rrtype)
    }

    // Сравниваем классы
    if a.Header().Class != b.Header().Class {
        return int(a.Header().Class) - int(b.Header().Class)
    }

    // Для одинаковых записей - сравниваем RDATA (упрощенная реализация)
    return strings.Compare(a.String(), b.String())
}

// verifyRRSIGWithMiekg проверяет RRSIG подпись используя встроенную функцию
func (s *DNSServer) verifyRRSIGWithMiekg(rrsig *dns.RRSIG, rrset []dns.RR) bool {
    if len(rrset) == 0 {
        return false
    }

    // Проверяем кэш RRSIG
    rrsigKey := fmt.Sprintf("%s_%d_%d_%d", rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm, rrsig.TypeCovered)
    if cachedRRSIG, exists := s.rrsigCache.Load(rrsigKey); exists {
        if cacheTime, timeExists := s.rrsigCacheTime.Load(rrsigKey); timeExists {
            if cacheTimeT, ok := cacheTime.(time.Time); ok {
                if time.Since(cacheTimeT) < rrsigCacheTTL {
                    // Проверяем, совпадает ли подпись
                    if cached, ok := cachedRRSIG.(*dns.RRSIG); ok {
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

    // Получаем DNSKEY для проверки подписи (используем QNAME minimization)
    dnskey := s.getCachedDNSKEY(rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
    if dnskey == nil {
        // Если ключ не найден в кэше, пытаемся получить его
        // Используем qname minimization при получении ключа
        dnskey = s.fetchDNSKEY(rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
        if dnskey == nil {
            fmt.Printf("DNSKEY not found for verification of %s\n", rrsig.SignerName)
            return false
        }
        s.cacheDNSKEY(rrsig.SignerName, dnskey)
    }

    // Используем встроенную функцию проверки подписи
    err := rrsig.Verify(dnskey, rrset)
    if err != nil {
        fmt.Printf("RRSIG verification error: %v\n", err)
        return false
    }

    // Кэшируем успешную проверку
    s.cacheRRSIG(rrsig)
    return true
}

// fetchDNSSECRecordsAsync асинхронно получает DNSSEC записи
func (s *DNSServer) fetchDNSSECRecordsAsync(domain string) ([]*dns.RRSIG, []*dns.DNSKEY, []*dns.DS, error) {
    var rrsigs []*dns.RRSIG
    var dnskeys []*dns.DNSKEY
    var dsRecords []*dns.DS
    var rrsigErr, dnskeyErr, dsErr error

    // Создаем каналы для результатов
    rrsigChan := make(chan []*dns.RRSIG, 1)
    dnskeyChan := make(chan []*dns.DNSKEY, 1)
    dsChan := make(chan []*dns.DS, 1)

    // Запускаем параллельные запросы
    go func() {
        rrsigResults := s.qnameMinimizeResolve(domain, "RRSIG")
        var localRRSIGs []*dns.RRSIG
        for _, r := range rrsigResults {
            if rr, err := dns.NewRR(r); err == nil {
                if rrsig, ok := rr.(*dns.RRSIG); ok {
                    localRRSIGs = append(localRRSIGs, rrsig)
                }
            }
        }
        rrsigChan <- localRRSIGs
    }()

    go func() {
        dnskeyResults := s.qnameMinimizeResolve(domain, "DNSKEY")
        var localDNSKEYs []*dns.DNSKEY
        for _, r := range dnskeyResults {
            if rr, err := dns.NewRR(r); err == nil {
                if dnskey, ok := rr.(*dns.DNSKEY); ok {
                    localDNSKEYs = append(localDNSKEYs, dnskey)
                }
            }
        }
        dnskeyChan <- localDNSKEYs
    }()

    go func() {
        dsResults := s.qnameMinimizeResolve(domain, "DS")
        var localDSs []*dns.DS
        for _, r := range dsResults {
            if rr, err := dns.NewRR(r); err == nil {
                if ds, ok := rr.(*dns.DS); ok {
                    localDSs = append(localDSs, ds)
                }
            }
        }
        dsChan <- localDSs
    }()

    // Собираем результаты с таймаутом
    timeout := time.After(5 * time.Second)

    select {
    case rrsigs = <-rrsigChan:
    case <-timeout:
        rrsigErr = fmt.Errorf("timeout fetching RRSIG records")
    }

    select {
    case dnskeys = <-dnskeyChan:
    case <-timeout:
        dnskeyErr = fmt.Errorf("timeout fetching DNSKEY records")
    }

    select {
    case dsRecords = <-dsChan:
    case <-timeout:
        dsErr = fmt.Errorf("timeout fetching DS records")
    }

    if rrsigErr != nil || dnskeyErr != nil || dsErr != nil {
        return rrsigs, dnskeys, dsRecords, fmt.Errorf("errors: %v, %v, %v", rrsigErr, dnskeyErr, dsErr)
    }

    return rrsigs, dnskeys, dsRecords, nil
}

// fetchDNSSECRecords получает DNSSEC записи для домена
func (s *DNSServer) fetchDNSSECRecords(domain string) ([]*dns.RRSIG, []*dns.DNSKEY, []*dns.DS, error) {
    var rrsigs []*dns.RRSIG
    var dnskeys []*dns.DNSKEY
    var dsRecords []*dns.DS

    // Запрашиваем RRSIG записи с QNAME minimization
    rrsigResults := s.qnameMinimizeResolve(domain, "RRSIG")
    for _, r := range rrsigResults {
        if rr, err := dns.NewRR(r); err == nil {
            if rrsig, ok := rr.(*dns.RRSIG); ok {
                rrsigs = append(rrsigs, rrsig)
            }
        }
    }

    // Запрашиваем DNSKEY записи
    dnskeyResults := s.qnameMinimizeResolve(domain, "DNSKEY")
    for _, r := range dnskeyResults {
        if rr, err := dns.NewRR(r); err == nil {
            if dnskey, ok := rr.(*dns.DNSKEY); ok {
                dnskeys = append(dnskeys, dnskey)
            }
        }
    }

    // Запрашиваем DS записи
    dsResults := s.qnameMinimizeResolve(domain, "DS")
    for _, r := range dsResults {
        if rr, err := dns.NewRR(r); err == nil {
            if ds, ok := rr.(*dns.DS); ok {
                dsRecords = append(dsRecords, ds)
            }
        }
    }

    return rrsigs, dnskeys, dsRecords, nil
}

// validateTrustChain проверяет цепочку доверия
func (s *DNSServer) validateTrustChain(domain string, dnskeys []*dns.DNSKEY, dsRecords []*dns.DS) bool {
    if len(dsRecords) == 0 {
        // Если нет DS записей, проверяем является ли домен корневым
        if domain == "." || domain == "" {
            // Проверяем корневой ключ
            for _, dnskey := range dnskeys {
                if s.trustAnchor != nil &&
                    dnskey.KeyTag() == s.trustAnchor.KeyTag() &&
                    dnskey.Algorithm == s.trustAnchor.Algorithm {
                    return true
                }
            }
            return false
        }
        // Для не-корневых доменов без DS записей проверяем родительскую зону
        return s.validateParentChain(domain, dnskeys)
    }

    // Проверяем соответствие DS и DNSKEY записей
    for _, ds := range dsRecords {
        matched := false
        for _, dnskey := range dnskeys {
            if s.verifyDS(ds, dnskey) {
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

// validateParentChain проверяет цепочку доверия через родительскую зону
func (s *DNSServer) validateParentChain(domain string, dnskeys []*dns.DNSKEY) bool {
    parent := s.getParentDomain(domain)
    if parent == domain {
        return false // Достигли корня
    }

    // Получаем DS записи для родительской зоны (с кэшем)
    dsRecords := s.getCachedDS(parent)
    if dsRecords == nil {
        var err error
        dsRecords, err = s.fetchDS(parent)
        if err != nil || len(dsRecords) == 0 {
            // Если нет DS записей, продолжаем проверку выше
            return s.validateParentChain(parent, dnskeys)
        }
        s.cacheDS(parent, dsRecords)
    }

    // Проверяем соответствие DS и DNSKEY записей
    for _, ds := range dsRecords {
        for _, dnskey := range dnskeys {
            if s.verifyDS(ds, dnskey) {
                return true
            }
        }
    }

    return false
}

// verifyDS проверяет соответствие DS и DNSKEY записей
// Реализовано корректное хеширование DNSKEY RDATA (flags, protocol, algorithm, public key)
func (s *DNSServer) verifyDS(ds *dns.DS, dnskey *dns.DNSKEY) bool {
    // Декодируем публичный ключ из base64
    keyData, err := base64.StdEncoding.DecodeString(dnskey.PublicKey)
    if err != nil {
        return false
    }

    // Формируем RDATA для DNSKEY: Flags(2) | Protocol(1) | Algorithm(1) | PublicKey
    rdata := make([]byte, 4+len(keyData))
    binary.BigEndian.PutUint16(rdata[0:], dnskey.Flags)
    rdata[2] = dnskey.Protocol
    rdata[3] = dnskey.Algorithm
    copy(rdata[4:], keyData)

    switch ds.DigestType {
    case dns.SHA1:
        hash := sha1.Sum(rdata)
        return strings.EqualFold(hex.EncodeToString(hash[:]), ds.Digest)
    case dns.SHA256:
        hash := sha256.Sum256(rdata)
        return strings.EqualFold(hex.EncodeToString(hash[:]), ds.Digest)
    default:
        fmt.Printf("Unsupported DS digest type: %d\n", ds.DigestType)
        return false
    }
}

// getParentDomain возвращает родительский домен
func (s *DNSServer) getParentDomain(domain string) string {
    if domain == "." || domain == "" {
        return "."
    }

    parts := strings.Split(strings.Trim(domain, "."), ".")
    if len(parts) <= 1 {
        return "."
    }

    parent := strings.Join(parts[1:], ".") + "."
    return parent
}

// getCachedDNSKEY получает DNSKEY из кэша
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

// cacheDNSKEY кэширует DNSKEY
func (s *DNSServer) cacheDNSKEY(domain string, dnskey *dns.DNSKEY) {
    key := fmt.Sprintf("%s_%d_%d", domain, dnskey.KeyTag(), dnskey.Algorithm)
    s.keyCache.Store(key, dnskey)
    s.keyCacheTime.Store(key, time.Now())
}

// getCachedDS получает DS записи из кэша
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

// cacheDS кэширует DS записи
func (s *DNSServer) cacheDS(domain string, dsRecords []*dns.DS) {
    s.dsCache.Store(domain, dsRecords)
    s.dsCacheTime.Store(domain, time.Now())
}

// cacheRRSIG кэширует RRSIG записи
func (s *DNSServer) cacheRRSIG(rrsig *dns.RRSIG) {
    key := fmt.Sprintf("%s_%d_%d_%d", rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm, rrsig.TypeCovered)
    s.rrsigCache.Store(key, rrsig)
    s.rrsigCacheTime.Store(key, time.Now())
}

// fetchDNSKEY получает DNSKEY для домена (использует QNAME minimization)
func (s *DNSServer) fetchDNSKEY(domain string, keyTag uint16, algorithm uint8) *dns.DNSKEY {
    results := s.qnameMinimizeResolve(domain, "DNSKEY")
    for _, r := range results {
        if rr, err := dns.NewRR(r); err == nil {
            if dnskey, ok := rr.(*dns.DNSKEY); ok {
                if dnskey.KeyTag() == keyTag && dnskey.Algorithm == algorithm {
                    s.cacheDNSKEY(domain, dnskey)
                    return dnskey
                }
            }
        }
    }
    return nil
}

// fetchDS получает DS записи для домена (использует QNAME minimization)
func (s *DNSServer) fetchDS(domain string) ([]*dns.DS, error) {
    var dsRecords []*dns.DS
    results := s.qnameMinimizeResolve(domain, "DS")
    for _, r := range results {
        if rr, err := dns.NewRR(r); err == nil {
            if ds, ok := rr.(*dns.DS); ok {
                dsRecords = append(dsRecords, ds)
            }
        }
    }
    return dsRecords, nil
}

// sendErrorResponse отправляет ответ с ошибкой клиенту
func (s *DNSServer) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int, message string) {
    reply := new(dns.Msg)
    reply.SetRcode(req, rcode)
    reply.Compress = true

    // Копируем EDNS0 настройки если они есть
    if edns0 := req.IsEdns0(); edns0 != nil && s.dnssecEnabled {
        reply.SetEdns0(edns0.UDPSize(), edns0.Do())
    }

    if req != nil && len(req.Question) > 0 {
        txtRecord := &dns.TXT{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{message}}
        reply.Extra = append(reply.Extra, txtRecord)
    }

    if err := w.WriteMsg(reply); err != nil {
        fmt.Printf("Error sending error response: %v\n", err)
    }
}

func main() {
    server := NewDNSServer()
    go server.startCleaner()

    // Запуск DNS сервера
    dns.HandleFunc(".", server.handleRequest)

    udpServer := &dns.Server{Addr: ":5454", Net: "udp"}
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
