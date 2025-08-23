package main

import (
    "context"
    "fmt"
    "net"
    "sync"
    "time"

    "github.com/domainr/dnsr"
    "github.com/miekg/dns"
    "golang.org/x/time/rate"
)

type DNSServer struct {
    resolver    *dnsr.Resolver
    rateLimiter *rate.Limiter
    visited     map[string]struct{}
    mu          sync.RWMutex
}

func NewDNSServer() *DNSServer {
    return &DNSServer{
        resolver:    dnsr.NewResolver(dnsr.WithCache(10000), dnsr.WithExpiry()),
        rateLimiter: rate.NewLimiter(rate.Every(time.Second), 100),
        visited:     make(map[string]struct{}),
    }
}

func (s *DNSServer) handleRequest(w dns.ResponseWriter, req *dns.Msg) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := s.rateLimiter.Wait(ctx); err != nil {
        s.sendErrorResponse(w, req, dns.RcodeServerFailure, "Rate limit exceeded")
        return
    }

    if len(req.Question) == 0 {
        s.sendErrorResponse(w, req, dns.RcodeFormatError, "No questions in request")
        return
    }

    question := req.Question[0]
    queryKey := fmt.Sprintf("%s:%d", question.Name, question.Qtype)

    s.mu.RLock()
    if _, exists := s.visited[queryKey]; exists {
        s.mu.RUnlock()
        s.sendErrorResponse(w, req, dns.RcodeRefused, "Potential loop detected")
        return
    }
    s.mu.RUnlock()

    s.mu.Lock()
    s.visited[queryKey] = struct{}{}
    s.mu.Unlock()

    defer func() {
        s.mu.Lock()
        delete(s.visited, queryKey)
        s.mu.Unlock()
    }()

    if len(s.visited) >= 10000 {
        s.mu.Lock()
        s.visited = make(map[string]struct{})
        s.mu.Unlock()
    }

    reply := new(dns.Msg)
    reply.SetReply(req)
    reply.Compress = true
    reply.RecursionAvailable = true

    qtypeStr, ok := dns.TypeToString[question.Qtype]
    if !ok {
        s.sendErrorResponse(w, req, dns.RcodeNotImplemented, "Unsupported QTYPE")
        return
    }

    results := s.resolver.Resolve(question.Name, qtypeStr)
    var hasValidAnswer bool

    for _, res := range results {
        rrStr := res.String()
        rr, err := dns.NewRR(rrStr)
        if err != nil {
            fmt.Printf("Failed to parse RR '%s': %v\n", rrStr, err)
            continue
        }
        reply.Answer = append(reply.Answer, rr)
        hasValidAnswer = true
    }

    if !hasValidAnswer {
        reply.SetRcode(req, dns.RcodeNameError)
    }

    if err := w.WriteMsg(reply); err != nil {
        fmt.Printf("Error writing response: %v\n", err)
    }
}

func (s *DNSServer) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int, message string) {
    reply := new(dns.Msg)
    reply.SetReply(req)
    reply.Compress = true
    reply.SetRcode(req, rcode)

    txtRecord := &dns.TXT{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{message}}
    reply.Extra = append(reply.Extra, txtRecord)

    if err := w.WriteMsg(reply); err != nil {
        fmt.Printf("Error sending error response: %v\n", err)
    }
}

func main() {
    server := NewDNSServer()

    udpServer := &dns.Server{Addr: ":5454", Net: "udp"}
    dns.HandleFunc(".", server.handleRequest)

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
