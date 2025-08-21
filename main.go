package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/domainr/dnsr"
	"github.com/miekg/dns"
)

const (
	listenPort = 5454
	cacheTTL   = 5 * time.Minute
)

// CacheEntry представляет запись в кэше
type cacheEntry struct {
	response []byte
	expiry   time.Time
}

// seenEntry для защиты от быстрых повторных запросов
type seenEntry struct {
	count int
	last  time.Time
}

var (
	cache       = make(map[string]cacheEntry)
	cacheHits   int
	cacheMisses int
	cacheMutex  sync.RWMutex

	resolver   *dnsr.Resolver
	localAddrs []net.IP // Список локальных IP-адресов сервера

	// Защита от циклов / флуда
	seenMutex          sync.Mutex
	seenRequests       = make(map[string]*seenEntry) // key = remoteIP|qname -> entry
	seenWindow         = 5 * time.Second
	seenCountThreshold = 3 // блокируем только после X повторов в окне

	inFlightMutex      sync.Mutex
	inFlight           = make(map[string]int) // qname -> count of current resolutions
	maxInFlightPerName = 10
)

func initResolver() {
	resolver = dnsr.NewResolver(
		dnsr.WithCache(10000),
		dnsr.WithTimeout(10*time.Second),
		dnsr.WithExpiry(),
		dnsr.WithTCPRetry(),
	)
}

func gatherLocalAddrs() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalf("Ошибка при получении сетевых интерфейсов: %v", err)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ipnet.IP.IsLoopback() {
				// не добавляем loopback — хотим разрешать тесты с 127.0.0.1
				continue
			}
			localAddrs = append(localAddrs, ipnet.IP)
		}
	}
	log.Printf("Обнаружены локальные IP-адреса: %v", localAddrs)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	initResolver()
	gatherLocalAddrs()

	// Фоновая очистка seenRequests
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			seenMutex.Lock()
			for k, e := range seenRequests {
				if now.Sub(e.last) > 10*seenWindow {
					delete(seenRequests, k)
				}
			}
			seenMutex.Unlock()
		}
	}()

	addr := fmt.Sprintf(":%d", listenPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("Ошибка при разрешении UDP-адреса: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Ошибка при запуске UDP-сервера: %v", err)
	}
	defer conn.Close()

	log.Printf("DNS-резолвер запущен на UDP-порту %d", listenPort)

	// Обработка сигналов для аккуратного завершения
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		log.Printf("Shutting down")
		conn.Close()
		os.Exit(0)
	}()

	buffer := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			// если conn.Close() вызван выше — выйдем
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return
			}
			log.Printf("Ошибка чтения из UDP: %v", err)
			continue
		}

		requestCopy := make([]byte, n)
		copy(requestCopy, buffer[:n])
		go handleRequest(conn, remoteAddr, requestCopy)
	}
}

func handleRequest(conn *net.UDPConn, remoteAddr *net.UDPAddr, request []byte) {
	// recover, чтобы единичная паника не уронила процесс
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic recovered in handleRequest: %v", r)
			_ = safeSendError(conn, remoteAddr, request, dns.RcodeServerFailure)
		}
	}()

	start := time.Now()
	msg := new(dns.Msg)
	if err := msg.Unpack(request); err != nil {
		log.Printf("Error unpacking DNS request from %s: %v", remoteAddr.String(), err)
		_ = safeSendError(conn, remoteAddr, msg, dns.RcodeFormatError)
		return
	}
	defer func() {
		log.Printf("Request from %s processed in %v", remoteAddr.String(), time.Since(start))
	}()

	if len(msg.Question) == 0 {
		_ = safeSendError(conn, remoteAddr, msg, dns.RcodeFormatError)
		return
	}

	// Проверки на цикл/флуд — делаем заранее
	var entered []string
	defer func() {
		for _, name := range entered {
			leaveInFlight(name)
		}
	}()

	for _, q := range msg.Question {
		qname := q.Name
		if isLoopDetected(remoteAddr.IP) {
			log.Printf("Detected direct loop from %s for %s — refused", remoteAddr.String(), qname)
			_ = safeSendError(conn, remoteAddr, msg, dns.RcodeRefused)
			return
		}

		if seenLikelyLoop(remoteAddr.IP, qname) {
			log.Printf("Seen-based loop/flood detected from %s for %s — refused", remoteAddr.String(), qname)
			_ = safeSendError(conn, remoteAddr, msg, dns.RcodeRefused)
			return
		}

		if !enterInFlight(qname) {
			log.Printf("In-flight limit exceeded for %s (from %s) — refused", qname, remoteAddr.String())
			_ = safeSendError(conn, remoteAddr, msg, dns.RcodeRefused)
			return
		}
		entered = append(entered, qname)
	}

	// Ключ кэша для первого вопроса
	cacheKey := ""
	firstQ := msg.Question[0]
	cacheKey = fmt.Sprintf("%s_%d", firstQ.Name, firstQ.Qtype)

	// Проверка кэша
	if cacheKey != "" {
		cacheMutex.RLock()
		entry, found := cache[cacheKey]
		if found && time.Now().Before(entry.expiry) {
			resp := make([]byte, len(entry.response))
			copy(resp, entry.response)
			cacheMutex.RUnlock()

			cacheHits++
			cachedMsg := new(dns.Msg)
			if err := cachedMsg.Unpack(resp); err == nil {
				cachedMsg.Id = msg.Id
				if b, err := cachedMsg.Pack(); err == nil {
					if _, err := conn.WriteToUDP(b, remoteAddr); err != nil {
						log.Printf("Error sending cached response to %s: %v", remoteAddr.String(), err)
					}
					log.Printf("Cache hit for %s from %s", cacheKey, remoteAddr.String())
				}
				return
			}
		} else {
			cacheMutex.RUnlock()
			cacheMisses++
			log.Printf("Cache miss for %s from %s", cacheKey, remoteAddr.String())
		}
	}

	// Формируем ответ
	responseMsg := new(dns.Msg)
	responseMsg.SetReply(msg)
	responseMsg.Compress = false
	responseMsg.Id = msg.Id

	anyAnswers := false
	anyNX := false

	for _, q := range msg.Question {
		answers, err := resolveQuestion(q)
		if err != nil {
			log.Printf("Error resolving %s: %v", q.Name, err)
			// Если это NXDOMAIN в dnsr — помечаем как NX
			if err != nil && err.Error() != "" {
				// Попытка определения NXDOMAIN по тексту ошибки dnsr
				// dnsr.ResolveErr возвращает dnsr.NXDOMAIN в ошибке, но сравнение по константе может быть ненадёжным
				// Здесь мы пометим как NX, но не превратим весь ответ в SERVFAIL
				anyNX = true
			}
			continue
		}
		if len(answers) > 0 {
			responseMsg.Answer = append(responseMsg.Answer, answers...)
			anyAnswers = true
		}
	}

	// Устанавливаем RCODE: если есть ответы — success, иначе NX или SERVFAIL
	if anyAnswers {
		responseMsg.MsgHdr.Rcode = dns.RcodeSuccess
	} else if anyNX {
		responseMsg.MsgHdr.Rcode = dns.RcodeNameError
	} else {
		responseMsg.MsgHdr.Rcode = dns.RcodeServerFailure
	}

	responseBytes, err := responseMsg.Pack()
	if err != nil {
		log.Printf("Error packing DNS response for %s: %v", cacheKey, err)
		_ = safeSendError(conn, remoteAddr, msg, dns.RcodeServerFailure)
		return
	}

	// Сохраняем в кэш для первого вопроса
	if cacheKey != "" && anyAnswers {
		cacheMutex.Lock()
		cache[cacheKey] = cacheEntry{response: responseBytes, expiry: time.Now().Add(cacheTTL)}
		cacheMutex.Unlock()
	}

	// Отправляем
	if _, err := conn.WriteToUDP(responseBytes, remoteAddr); err != nil {
		log.Printf("Error sending response to %s: %v", remoteAddr.String(), err)
	}
}

// safeSendError формирует и отправляет ответ об ошибке без паники
func safeSendError(conn *net.UDPConn, remoteAddr *net.UDPAddr, msgOrRaw interface{}, rcode int) error {
	var msg *dns.Msg
	switch v := msgOrRaw.(type) {
	case *dns.Msg:
		msg = v
	case []byte:
		m := new(dns.Msg)
		if err := m.Unpack(v); err == nil {
			msg = m
		}
	}

	resp := new(dns.Msg)
	if msg != nil {
		resp.SetReply(msg)
		resp.MsgHdr.Rcode = rcode
		resp.Id = msg.Id
	} else {
		resp.MsgHdr.Rcode = rcode
	}
	resp.Compress = false
	b, err := resp.Pack()
	if err != nil {
		log.Printf("Ошибка упаковки служебного ответа: %v", err)
		return err
	}
	if _, err := conn.WriteToUDP(b, remoteAddr); err != nil {
		log.Printf("Ошибка отправки служебного ответа по UDP: %v", err)
		return err
	}
	return nil
}

// seenLikelyLoop возвращает true, если по seen-cache запрос выглядит как цикл/флуд.
// Блокируем только когда count >= seenCountThreshold в пределах seenWindow.
func seenLikelyLoop(remoteIP net.IP, qname string) bool {
	if remoteIP == nil {
		return false
	}
	key := fmt.Sprintf("%s|%s", remoteIP.String(), qname)
	now := time.Now()

	seenMutex.Lock()
	defer seenMutex.Unlock()

	e, ok := seenRequests[key]
	if !ok || now.Sub(e.last) > seenWindow {
		seenRequests[key] = &seenEntry{count: 1, last: now}
		return false
	}

	e.count++
	e.last = now
	if e.count >= seenCountThreshold {
		log.Printf("seenLikelyLoop: %s requested %s %d times within %v — treating as loop/flood",
			remoteIP.String(), qname, e.count, seenWindow)
		return true
	}
	return false
}

// enterInFlight пытается пометить qname как in-flight. Возвращает true, если разрешено.
func enterInFlight(qname string) bool {
	inFlightMutex.Lock()
	defer inFlightMutex.Unlock()
	cnt := inFlight[qname]
	if cnt >= maxInFlightPerName {
		return false
	}
	inFlight[qname] = cnt + 1
	return true
}

// leaveInFlight снимает метку in-flight для qname
func leaveInFlight(qname string) {
	inFlightMutex.Lock()
	defer inFlightMutex.Unlock()
	if inFlight[qname] <= 1 {
		delete(inFlight, qname)
		return
	}
	inFlight[qname]--
}

func resolveQuestion(q dns.Question) ([]dns.RR, error) {
	var answers []dns.RR

	// Контекст с таймаутом — пока не передаём в dnsr, но оставим для расширений
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ctx

	qtype := dns.TypeToString[q.Qtype]
	if qtype == "" {
		return nil, fmt.Errorf("unsupported query type %d for %s", q.Qtype, q.Name)
	}

	rrs, err := resolver.ResolveErr(q.Name, qtype)
	if err != nil {
		if err == dnsr.NXDOMAIN {
			return nil, fmt.Errorf("domain %s does not exist: %w", q.Name, err)
		}
		return nil, fmt.Errorf("failed to resolve %s %s: %w", q.Name, qtype, err)
	}

	for _, rr := range rrs {
		rtype := dns.StringToType[rr.Type]
		if rtype == 0 {
			log.Printf("Skipping unknown RR type %q for %s", rr.Type, rr.Name)
			continue
		}
		hdr := dns.RR_Header{Name: dns.Fqdn(rr.Name), Rrtype: rtype, Class: dns.ClassINET, Ttl: uint32(rr.TTL / time.Second)}
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
				log.Printf("Invalid AAAA record for %s: %s", q.Name, rr.Value)
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
			log.Printf("Unsupported record type: %s for %s — skipped", rr.Type, rr.Name)
			continue
		}
	}

	log.Printf("Resolved %s %s: %d records", q.Name, qtype, len(answers))

	if len(answers) == 0 && len(rrs) == 0 {
		return nil, fmt.Errorf("no records found for %s %s", q.Name, qtype)
	}
	return answers, nil
}

func isLoopDetected(remoteIP net.IP) bool {
	if remoteIP == nil {
		return false
	}
	for _, localIP := range localAddrs {
		if localIP.Equal(remoteIP) {
			return true
		}
	}
	return false
}

func printCacheStats() {
	log.Printf("Cache hits: %d, cache misses: %d", cacheHits, cacheMisses)
}
