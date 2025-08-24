package main

import (
    "fmt"
    "net"
    "sync"
    "time"

    "github.com/domainr/dnsr"
    "github.com/miekg/dns"
)

// DNSServer содержит все необходимые компоненты DNS-сервера
type DNSServer struct {
    resolver        *dnsr.Resolver
    visited         map[string]time.Time
    mu              sync.RWMutex
    nxdomainCounter map[string]int
    nxdomainLastSeen map[string]time.Time // Добавляем map для времени последнего NXDOMAIN
    quarantined     map[string]time.Time
}

const (
    nxdomainLimit = 3
)

// NewDNSServer создаёт и инициализирует новый DNS-сервер
func NewDNSServer() *DNSServer {
    return &DNSServer{
        resolver:        dnsr.NewResolver(),
        visited:         make(map[string]time.Time),
        nxdomainCounter: make(map[string]int),
        nxdomainLastSeen: make(map[string]time.Time), // Инициализируем
        quarantined:     make(map[string]time.Time),
    }
}

// startCleaner запускает фоновую горутину для очистки visited map
func (s *DNSServer) startCleaner() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    for range ticker.C {
        s.mu.Lock()
        
        // Очистка visited map
        visitedCount := 0
        for key, ts := range s.visited {
            if time.Since(ts) > 10*time.Minute {
                delete(s.visited, key)
                visitedCount++
            }
        }
        
        // "Умная" очистка nxdomainCounter
        nxdomainCount := 0
        for domain, lastSeen := range s.nxdomainLastSeen {
            if time.Since(lastSeen) > 30*time.Minute {
                delete(s.nxdomainCounter, domain)
                delete(s.nxdomainLastSeen, domain)
                nxdomainCount++
            }
        }

        // Снятие доменов с карантина
        quarantineCount := 0
        for domain, releaseTime := range s.quarantined {
            if time.Now().After(releaseTime) {
                delete(s.quarantined, domain)
                quarantineCount++
            }
        }

        s.mu.Unlock()
        fmt.Printf("Cleaned %d old entries from visited map.\n", visitedCount)
        fmt.Printf("Reset %d NXDOMAIN counters due to inactivity.\n", nxdomainCount)
        fmt.Printf("Released %d domains from quarantine.\n", quarantineCount)
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

    s.mu.RLock()
    // Проверяем, не находится ли домен на карантине
    if releaseTime, isQuarantined := s.quarantined[question.Name]; isQuarantined {
        if time.Now().Before(releaseTime) {
            s.mu.RUnlock()
            s.sendErrorResponse(w, req, dns.RcodeNameError, "Domain temporarily quarantined")
            return
        }
    }
    // Проверка на потенциальную рекурсию
    _, exists := s.visited[queryKey]
    s.mu.RUnlock()

    if exists {
        s.sendErrorResponse(w, req, dns.RcodeRefused, "Potential query loop detected")
        return
    }

    s.mu.Lock()
    s.visited[queryKey] = time.Now()
    if len(s.visited) > 100000 {
        s.visited = make(map[string]time.Time)
        fmt.Println("Visited map cleared due to reaching size limit.")
    }
    s.mu.Unlock()

    defer func() {
        s.mu.Lock()
        delete(s.visited, queryKey)
        s.mu.Unlock()
    }()

    reply := new(dns.Msg)
    reply.SetReply(req)
    reply.Compress = true
    reply.RecursionAvailable = true

    qtypeStr, ok := dns.TypeToString[question.Qtype]
    if !ok {
        s.sendErrorResponse(w, req, dns.RcodeNotImplemented, "Unsupported QTYPE")
        return
    }

    // Выполняем рекурсивный запрос
    results := s.resolver.Resolve(question.Name, qtypeStr)
    var hasValidAnswer bool

    for _, res := range results {
        // Проверяем, что ответ не является NXDOMAIN
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

    if !hasValidAnswer {
        s.mu.Lock()
        s.nxdomainCounter[question.Name]++
        s.nxdomainLastSeen[question.Name] = time.Now() // Обновляем время последнего запроса

        if s.nxdomainCounter[question.Name] >= nxdomainLimit {
            // Изменение времени блокировки и сообщения
            fmt.Printf("NXDOMAIN limit reached for '%s'. Quarantining for 30 seconds.\n", question.Name)
            s.quarantined[question.Name] = time.Now().Add(30 * time.Second)
        }
        s.mu.Unlock()

        reply.SetRcode(req, dns.RcodeNameError)
        if err := w.WriteMsg(reply); err != nil {
            fmt.Printf("Error writing response: %v\n", err)
        }
        return
    }

    s.mu.Lock()
    delete(s.nxdomainCounter, question.Name)
    delete(s.nxdomainLastSeen, question.Name)
    s.mu.Unlock()

    if err := w.WriteMsg(reply); err != nil {
        fmt.Printf("Error writing response: %v\n", err)
    }
}

// sendErrorResponse отправляет ответ с ошибкой клиенту
func (s *DNSServer) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int, message string) {
    reply := new(dns.Msg)
    if req != nil && len(req.Question) > 0 {
        reply.SetReply(req)
    } else {
        reply.SetRcode(req, rcode)
    }

    reply.Compress = true
    reply.SetRcode(req, rcode)

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
