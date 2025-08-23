package main

import (
    "context"
    "fmt"
    "log"
    "net"
    "runtime/debug"
    "sync"
    "time"

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

type DNSResolver interface {
	LookupHost(host string) ([]net.IP, error)
	LookupTXT(host string) ([]string, error)
	LookupMX(host string) ([]*net.MX, error)
	LookupCNAME(host string) (string, error)
	LookupNS(host string) ([]*net.NS, error)
}

// MiekgDNSResolver implements the DNSResolver interface using miekg/dns.
type MiekgDNSResolver struct {
	Client *dns.Client
}

// NewMiekgDNSResolver creates a new MiekgDNSResolver.
func NewMiekgDNSResolver() *MiekgDNSResolver {
	return &MiekgDNSResolver{
		Client: new(dns.Client),
	}
}

// LookupHost performs an A record lookup.
func (r *MiekgDNSResolver) LookupHost(host string) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)

	resp, _, err := r.Client.Exchange(msg, "8.8.8.8:53") // Using Google's DNS for now
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}
	return ips, nil
}

// LookupTXT performs a TXT record lookup.
func (r *MiekgDNSResolver) LookupTXT(host string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeTXT)

	resp, _, err := r.Client.Exchange(msg, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	var txts []string
	for _, ans := range resp.Answer {
		if t, ok := ans.(*dns.TXT); ok {
			txts = append(txts, t.Txt...)
		}
	}
	return txts, nil
}

// LookupMX performs an MX record lookup.
func (r *MiekgDNSResolver) LookupMX(host string) ([]*net.MX, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeMX)

	resp, _, err := r.Client.Exchange(msg, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	var mxs []*net.MX
	for _, ans := range resp.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			mxs = append(mxs, &net.MX{Host: mx.Mx, Pref: mx.Preference})
		}
	}
	return mxs, nil
}

// LookupCNAME performs a CNAME record lookup.
func (r *MiekgDNSResolver) LookupCNAME(host string) (string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeCNAME)

	resp, _, err := r.Client.Exchange(msg, "8.8.8.8:53")
	if err != nil {
		return "", err
	}

	for _, ans := range resp.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			return cname.Target, nil
		}
	}
	return "", fmt.Errorf("no CNAME record for %s", host)
}

// LookupNS performs an NS record lookup.
func (r *MiekgDNSResolver) LookupNS(host string) ([]*net.NS, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeNS)

	resp, _, err := r.Client.Exchange(msg, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	var nss []*net.NS
	for _, ans := range resp.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nss = append(nss, &net.NS{Host: ns.Ns})
		}
	}
	return nss, nil
}

var (
	resolver DNSResolver = NewMiekgDNSResolver()
	semaphore          = make(chan struct{}, maxConcurrentRequests)
    cache              = make(map[string]cacheEntry)
	cacheHits          int
	cacheMisses        int
	cacheMutex         sync.RWMutex
	cleanupTicker      *time.Ticker
	stopCleanupChannel chan struct{}
)

func init() {
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

func runServer() {
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
    startDNSServer(conn)
}



func startDNSServer(conn *net.UDPConn) {
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

            ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
            defer cancel()
            handleRequest(ctx, conn, remoteAddr, requestCopy)
        }()
    }
}

func handleRequest(ctx context.Context, conn *net.UDPConn, remoteAddr *net.UDPAddr, request []byte) {
    startTime := time.Now()
    msg := new(dns.Msg)

    defer func() {
        if r := recover(); r != nil {
            log.Printf("Паника в handleRequest: %v\n%s", r, debug.Stack())
            sendErrorResponse(conn, remoteAddr, msg, dns.RcodeServerFailure)
        }
    }()

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
            responseMsg.SetRcode(msg, dns.RcodeServerFailure)
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

    defer func() {
        if r := recover(); r != nil {
            log.Printf("Паника в resolveQuestion: %v\n%s", r, debug.Stack())
        }
    }()

    qtype := dns.TypeToString[q.Qtype]
    if qtype == "" {
        return nil, fmt.Errorf("неподдерживаемый тип запроса %d для %s", q.Qtype, q.Name)
    }

    if isRecursiveLoop(q.Name) {
        return nil, fmt.Errorf("обнаружено рекурсивное обращение для домена %s", q.Name)
    }

    var err error
    var foundRecords bool

    switch q.Qtype {
    case dns.TypeA:
        ips, lookupErr := resolver.LookupHost(q.Name)
        if lookupErr != nil {
            err = lookupErr
        } else {
            foundRecords = true
            for _, ip := range ips {
                hdr := dns.RR_Header{
                    Name:   dns.Fqdn(q.Name),
                    Rrtype: dns.TypeA,
                    Class:  dns.ClassINET,
                    Ttl:    300, // Default TTL
                }
                answers = append(answers, &dns.A{Hdr: hdr, A: ip.To4()})
            }
        }
    case dns.TypeAAAA:
        // bogdanovich/dns_resolver does not directly support AAAA, need to implement or find alternative
        // For now, we'll skip AAAA or use a different approach if needed.
        log.Printf("AAAA record type not directly supported by bogdanovich/dns_resolver, skipping for %s", q.Name)
        return nil, fmt.Errorf("AAAA record type not directly supported")
    case dns.TypeCNAME:
        cname, lookupErr := resolver.LookupCNAME(q.Name)
        if lookupErr != nil {
            err = lookupErr
        } else if cname != "" {
            foundRecords = true
            hdr := dns.RR_Header{
                Name:   dns.Fqdn(q.Name),
                Rrtype: dns.TypeCNAME,
                Class:  dns.ClassINET,
                Ttl:    300, // Default TTL
            }
            answers = append(answers, &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(cname)})
            // Recursively resolve the CNAME target
            cnameTargetAnswers, cnameTargetErr := resolveQuestion(ctx, dns.Question{Name: dns.Fqdn(cname), Qtype: dns.TypeA, Qclass: dns.ClassINET})
            if cnameTargetErr == nil {
                answers = append(answers, cnameTargetAnswers...)
            } else {
                log.Printf("Ошибка разрешения цели CNAME %s: %v", cname, cnameTargetErr)
            }
        }
    case dns.TypeMX:
        mxs, lookupErr := resolver.LookupMX(q.Name)
        if lookupErr != nil {
            err = lookupErr
        } else {
            foundRecords = true
            for _, mx := range mxs {
                hdr := dns.RR_Header{
                    Name:   dns.Fqdn(q.Name),
                    Rrtype: dns.TypeMX,
                    Class:  dns.ClassINET,
                    Ttl:    300, // Default TTL
                }
                answers = append(answers, &dns.MX{Hdr: hdr, Preference: mx.Pref, Mx: dns.Fqdn(mx.Host)})
            }
        }
    case dns.TypeNS:
        nss, lookupErr := resolver.LookupNS(q.Name)
        if lookupErr != nil {
            err = lookupErr
        } else {
            foundRecords = true
            for _, ns := range nss {
                hdr := dns.RR_Header{
                    Name:   dns.Fqdn(q.Name),
                    Rrtype: dns.TypeNS,
                    Class:  dns.ClassINET,
                    Ttl:    300, // Default TTL
                }
                answers = append(answers, &dns.NS{Hdr: hdr, Ns: dns.Fqdn(ns.Host)})
            }
        }
    case dns.TypeTXT:
        txts, lookupErr := resolver.LookupTXT(q.Name)
        if lookupErr != nil {
            err = lookupErr
        } else {
            foundRecords = true
            for _, txt := range txts {
                hdr := dns.RR_Header{
                    Name:   dns.Fqdn(q.Name),
                    Rrtype: dns.TypeTXT,
                    Class:  dns.ClassINET,
                    Ttl:    300, // Default TTL
                }
                answers = append(answers, &dns.TXT{Hdr: hdr, Txt: []string{txt}})
            }
        }
    default:
        return nil, fmt.Errorf("неподдерживаемый тип запроса: %s", qtype)
    }

    if err != nil {
        log.Printf("Ошибка разрешения %s %s: %v", q.Name, qtype, err)
        return nil, fmt.Errorf("ошибка разрешения %s %s: %w", q.Name, qtype, err)
    }

    if !foundRecords && len(answers) == 0 {
        return nil, fmt.Errorf("нет записей для %s %s", q.Name, qtype)
    }

    log.Printf("Разрешено %s %s: %d записей", q.Name, qtype, len(answers))


    return answers, nil
}

func isRecursiveLoop(domain string) bool {
    // Проверяем, является ли домен локальным адресом или IP-адресом
    if domain == "localhost." || domain == "127.0.0.1." || net.ParseIP(domain) != nil {
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