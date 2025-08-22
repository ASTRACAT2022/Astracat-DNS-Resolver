package main

import (
    "context"
    "fmt"
    "log"
    "net"
    "runtime/debug"
    "sync"
    "time"

    "github.com/domainr/dnsr"
    "github.com/miekg/dns"
)

const (
    listenPort               = 5454
    maxConcurrentRequests    = 100
    cacheCleanupInterval     = 1 * time.Minute
    defaultCacheExpiration   = 5 * time.Minute
    minimumAllowedTTL        = 1 * time.Second
)

type cacheEntry struct {
    response []byte
    expiry   time.Time
}

var (
    semaphore          = make(chan struct{}, maxConcurrentRequests)
    cache              = make(map[string]cacheEntry)
    cacheHits          int
    cacheMisses        int
    cacheMutex         sync.RWMutex
    resolver           *dnsr.Resolver
    cleanupTicker      *time.Ticker
    stopCleanupChannel chan struct{}
)

func init() {
    resolver = dnsr.NewResolver(
        dnsr.WithCache(10000),
        dnsr.WithTimeout(10*time.Second),
        dnsr.WithExpiry(),
        dnsr.WithTCPRetry(),
    )

    stopCleanupChannel = make(chan struct{})
    cleanupTicker = time.NewTicker(cacheCleanupInterval)
    go cleanupCache()
}

func cleanupCache() {
    for {
        select {
        case <-cleanupTicker.C:
            now := time.Now()
            cacheMutex.Lock()
            for key, entry := range cache {
                if now.After(entry.expiry) {
                    delete(cache, key)
                }
            }
            cacheMutex.Unlock()
        case <-stopCleanupChannel:
            return
        }
    }
}

func main() {
    defer cleanupTicker.Stop()
    defer close(stopCleanupChannel)

    addr := fmt.Sprintf("127.0.0.1:%d", listenPort)
    udpAddr, err := net.ResolveUDPAddr("udp", addr)
    if err != nil {
        log.Fatalf("Ошибка при разрешении UDP-адреса: %v", err)
    }
    conn, err := net.ListenUDP("udp", udpAddr)
    if err != nil {
        log.Fatalf("Ошибка при запуске UDP-сервера: %v", err)
    }
    defer conn.Close()

    log.Printf("DNS-резолвер запущен на UDP-адресе %s", addr)
    buffer := make([]byte, 1024)

    for {
        n, remoteAddr, err := conn.ReadFromUDP(buffer)
        if err != nil {
            log.Printf("Ошибка чтения из UDP: %v", err)
            continue
        }

        requestCopy := make([]byte, n)
        copy(requestCopy, buffer[:n])

        go func() {
            semaphore <- struct{}{}
            defer func() {
                <-semaphore
                if r := recover(); r != nil {
                    log.Printf("Паника в горутине: %v\n%s", r, debug.Stack())
                }
            }()

            ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
            defer cancel()
            handleRequest(ctx, conn, remoteAddr, requestCopy)
        }()
    }
}

func handleRequest(ctx context.Context, conn *net.UDPConn, remoteAddr *net.UDPAddr, request []byte) {
    startTime := time.Now()
    msg := new(dns.Msg)
    if err := msg.Unpack(request); err != nil {
        log.Printf("Ошибка распаковки DNS-запроса от %s: %v", remoteAddr.String(), err)
        sendErrorResponse(conn, remoteAddr, msg, dns.RcodeServerFailure)
        return
    }

    defer func() {
        duration := time.Since(startTime)
        log.Printf("Запрос от %s обработан за %v", remoteAddr.String(), duration)
    }()

    cacheKey := ""
    if len(msg.Question) > 0 {
        q := msg.Question[0]
        cacheKey = fmt.Sprintf("%s_%d", q.Name, q.Qtype)
    }

    if cacheKey != "" {
        cacheMutex.RLock()
        if entry, found := cache[cacheKey]; found && time.Now().Before(entry.expiry) {
            cacheMutex.RUnlock()
            cacheHits++
            cachedMsg := new(dns.Msg)
            if err := cachedMsg.Unpack(entry.response); err == nil {
                cachedMsg.Id = msg.Id
                responseBytes, err := cachedMsg.Pack()
                if err == nil {
                    _, err = conn.WriteToUDP(responseBytes, remoteAddr)
                    if err != nil {
                        log.Printf("Ошибка отправки кэшированного ответа на %s: %v", remoteAddr.String(), err)
                    }
                    log.Printf("Успешное попадание в кэш для %s от %s", cacheKey, remoteAddr.String())
                    return
                }
            }
        }
        cacheMutex.RUnlock()
        cacheMisses++
        log.Printf("Промах кэша для %s от %s", cacheKey, remoteAddr.String())
    }

    responseMsg := new(dns.Msg)
    responseMsg.SetReply(msg)
    responseMsg.Compress = false
    responseMsg.Id = msg.Id

    var allAnswers []dns.RR
    for _, q := range msg.Question {
        answers, err := resolveQuestion(ctx, q)
        if err != nil {
            log.Printf("Ошибка разрешения DNS-вопроса для %s от %s: %v", q.Name, remoteAddr.String(), err)
            responseMsg.SetRcode(msg, dns.RcodeNameError)
            continue
        }
        allAnswers = append(allAnswers, answers...)
    }

    responseMsg.Answer = allAnswers

    responseBytes, err := responseMsg.Pack()
    if err != nil {
        log.Printf("Ошибка упаковки DNS-ответа для %s от %s: %v", cacheKey, remoteAddr.String(), err)
        sendErrorResponse(conn, remoteAddr, msg, dns.RcodeServerFailure)
        return
    }

    if cacheKey != "" && len(allAnswers) > 0 {
        ttl := calculateMinTTL(allAnswers)
        if ttl <= minimumAllowedTTL {
            ttl = defaultCacheExpiration
        }
        cacheMutex.Lock()
        cache[cacheKey] = cacheEntry{
            response: responseBytes,
            expiry:   time.Now().Add(ttl),
        }
        cacheMutex.Unlock()
    }

    select {
    case <-ctx.Done():
        log.Printf("Запрос отменен из-за истечения таймаута: %v", ctx.Err())
        return
    default:
        _, err = conn.WriteToUDP(responseBytes, remoteAddr)
        if err != nil {
            log.Printf("Ошибка отправки ответа на %s: %v", remoteAddr.String(), err)
        }
    }
}

func calculateMinTTL(answers []dns.RR) time.Duration {
    minTtl := time.Hour
    for _, answer := range answers {
        currentTtl := time.Duration(answer.Header().Ttl) * time.Second
        if currentTtl < minTtl {
            minTtl = currentTtl
        }
    }
    return minTtl
}

func resolveQuestion(ctx context.Context, q dns.Question) ([]dns.RR, error) {
    var answers []dns.RR

    qtype := dns.TypeToString[q.Qtype]
    if qtype == "" {
        return nil, fmt.Errorf("неподдерживаемый тип запроса %d для %s", q.Qtype, q.Name)
    }

    if isRecursiveLoop(q.Name) {
        return nil, fmt.Errorf("обнаружено рекурсивное обращение для домена %s", q.Name)
    }

    rrs, err := resolver.ResolveErr(q.Name, qtype)
    if err != nil {
        if err == dnsr.NXDOMAIN {
            return nil, fmt.Errorf("домен %s не найден: %w", q.Name, err)
        }
        return nil, fmt.Errorf("ошибка разрешения %s %s: %w", q.Name, qtype, err)
    }

    for _, rr := range rrs {
        hdr := dns.RR_Header{
            Name:   dns.Fqdn(rr.Name),
            Rrtype: dns.StringToType[rr.Type],
            Class:  dns.ClassINET,
            Ttl:    uint32(rr.TTL / time.Second),
        }

        switch rr.Type {
        case "A":
            ip := net.ParseIP(rr.Value)
            if ip == nil || ip.To4() == nil {
                continue
            }
            answers = append(answers, &dns.A{Hdr: hdr, A: ip.To4()})
        case "AAAA":
            ip := net.ParseIP(rr.Value)
            if ip == nil || ip.To16() == nil || ip.To4() != nil {
                log.Printf("Недопустимая запись AAAA для %s: %s", q.Name, rr.Value)
                continue
            }
            answers = append(answers, &dns.AAAA{Hdr: hdr, AAAA: ip})
        case "MX":
            answers = append(answers, &dns.MX{Hdr: hdr, Preference: 10, Mx: dns.Fqdn(rr.Value)})
        case "NS":
            answers = append(answers, &dns.NS{Hdr: hdr, Ns: dns.Fqdn(rr.Value)})
        case "CNAME":
            answers = append(answers, &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(rr.Value)})
        case "TXT":
            answers = append(answers, &dns.TXT{Hdr: hdr, Txt: []string{rr.Value}})
        case "SOA":
            continue
        default:
            log.Printf("Неподдерживаемый тип записи: %s для %s", rr.Type, rr.Name)
            continue
        }
    }

    log.Printf("Разрешено %s %s: %d записей", q.Name, qtype, len(answers))

    if len(answers) == 0 && len(rrs) == 0 {
        return nil, fmt.Errorf("нет записей для %s %s", q.Name, qtype)
    }

    return answers, nil
}

func isRecursiveLoop(domain string) bool {
    if domain == "example.com" && net.ParseIP(domain) != nil {
        return true
    }
    return false
}

func sendErrorResponse(conn *net.UDPConn, remoteAddr *net.UDPAddr, msg *dns.Msg, rcode int) {
    responseMsg := new(dns.Msg)
    responseMsg.SetRcode(msg, rcode)
    responseMsg.Compress = false
    responseMsg.Id = msg.Id
    responseBytes, err := responseMsg.Pack()
    if err != nil {
        log.Printf("Ошибка упаковки ответа об ошибке: %v", err)
        return
    }
    _, err = conn.WriteToUDP(responseBytes, remoteAddr)
    if err != nil {
        log.Printf("Ошибка отправки ответа об ошибке по UDP: %v", err)
    }
    printCacheStats()
}

func printCacheStats() {
    log.Printf("Попадания в кэш: %d, промахи кэша: %d", cacheHits, cacheMisses)
}