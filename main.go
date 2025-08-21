package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
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

var (
	cache       = make(map[string]cacheEntry)
	cacheHits   int
	cacheMisses int
	cacheMutex  sync.RWMutex
	resolver    *dnsr.Resolver
	localAddrs  []net.IP // Список локальных IP-адресов сервера
)

func init() {
	// Инициализируем Resolver из пакета dnsr
	resolver = dnsr.NewResolver(
		dnsr.WithCache(10000),         // Кэш на 10000 записей, как в примере
		dnsr.WithTimeout(10*time.Second), // Увеличенный таймаут 10 секунд
		dnsr.WithExpiry(),              // Очистка устаревших записей по TTL
		dnsr.WithTCPRetry(),            // Повтор по TCP при усечении
	)

	// Получаем локальные IP-адреса для предотвращения зацикливания
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalf("Ошибка при получении сетевых интерфейсов: %v", err)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				localAddrs = append(localAddrs, ipnet.IP)
			}
		}
	}
	log.Printf("Обнаружены локальные IP-адреса: %v", localAddrs)
}

func main() {
	// Запускаем DNS-сервер
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

	// Буфер для входящих запросов
	buffer := make([]byte, 1024)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Ошибка чтения из UDP: %v", err)
			continue
		}

		// Копируем буфер для избежания гонки данных
		requestCopy := make([]byte, n)
		copy(requestCopy, buffer[:n])
		go handleRequest(conn, remoteAddr, requestCopy)
	}
}

func handleRequest(conn *net.UDPConn, remoteAddr *net.UDPAddr, request []byte) {
	// Защита от зацикливания: игнорируем запросы от самого себя
	if isLoopDetected(remoteAddr.IP) {
		log.Printf("Обнаружен цикл DNS-запроса от %s. Запрос проигнорирован.", remoteAddr.String())
		return
	}

	startTime := time.Now()
	// Парсим входящий DNS-запрос
	msg := new(dns.Msg)
	if err := msg.Unpack(request); err != nil {
		log.Printf("Error unpacking DNS request from %s: %v", remoteAddr.String(), err)
		sendErrorResponse(conn, remoteAddr, msg, dns.RcodeServerFailure)
		return
	}
	defer func() {
		duration := time.Since(startTime)
		log.Printf("Request from %s processed in %v", remoteAddr.String(), duration)
	}()

	// Формируем ключ кэша
	cacheKey := ""
	if len(msg.Question) > 0 {
		q := msg.Question[0]
		cacheKey = fmt.Sprintf("%s_%d", q.Name, q.Qtype)
	}

	// Проверяем кэш приложения
	if cacheKey != "" {
		cacheMutex.RLock()
		if entry, found := cache[cacheKey]; found && time.Now().Before(entry.expiry) {
			cacheMutex.RUnlock()
			cacheHits++
			// Обновляем ID для кэшированного ответа
			cachedMsg := new(dns.Msg)
			if err := cachedMsg.Unpack(entry.response); err == nil {
				cachedMsg.Id = msg.Id
				responseBytes, err := cachedMsg.Pack()
				if err == nil {
					_, err = conn.WriteToUDP(responseBytes, remoteAddr)
					if err != nil {
						log.Printf("Error sending cached response to %s: %v", remoteAddr.String(), err)
					}
					log.Printf("Cache hit for %s from %s", cacheKey, remoteAddr.String())
				}
				return
			}
		}
		cacheMutex.RUnlock()
		cacheMisses++
		log.Printf("Cache miss for %s from %s", cacheKey, remoteAddr.String())
	}

	// Создаём ответ
	responseMsg := new(dns.Msg)
	responseMsg.SetReply(msg)
	responseMsg.Compress = false
	responseMsg.Id = msg.Id // Устанавливаем правильный ID

	// Обрабатываем вопросы с помощью dnsr.Resolver
	for _, q := range msg.Question {
		answers, err := resolveQuestion(q)
		if err != nil {
			log.Printf("Error resolving DNS question for %s from %s: %v", q.Name, remoteAddr.String(), err)
			responseMsg.SetRcode(msg, dns.RcodeNameError)
			continue
		}
		responseMsg.Answer = append(responseMsg.Answer, answers...)
	}

	// Упаковываем ответ
	responseBytes, err := responseMsg.Pack()
	if err != nil {
		log.Printf("Error packing DNS response for %s from %s: %v", cacheKey, remoteAddr.String(), err)
		sendErrorResponse(conn, remoteAddr, msg, dns.RcodeServerFailure)
		return
	}

	// Сохраняем в кэш приложения, если есть ответы
	if cacheKey != "" && len(responseMsg.Answer) > 0 {
		cacheMutex.Lock()
		cache[cacheKey] = cacheEntry{
			response: responseBytes,
			expiry:   time.Now().Add(cacheTTL),
		}
		cacheMutex.Unlock()
	}

	// Отправляем ответ клиенту
	_, err = conn.WriteToUDP(responseBytes, remoteAddr)
	if err != nil {
		log.Printf("Error sending response to %s: %v", remoteAddr.String(), err)
	}
	// TODO: Profile the code to identify performance bottlenecks
}

func resolveQuestion(q dns.Question) ([]dns.RR, error) {
	var answers []dns.RR

	// Создаём контекст с таймаутом
	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Преобразуем тип запроса в строку для dnsr
	qtype := dns.TypeToString[q.Qtype]
	if qtype == "" {
		return nil, fmt.Errorf("unsupported query type %d for %s", q.Qtype, q.Name)
	}

	// Используем Resolver для разрешения запроса
	rrs, err := resolver.ResolveErr(q.Name, qtype)
	if err != nil {
		if err == dnsr.NXDOMAIN {
			return nil, fmt.Errorf("domain %s does not exist: %w", q.Name, err)
		}
		return nil, fmt.Errorf("failed to resolve %s %s: %w", q.Name, qtype, err)
	}

	// Преобразуем dnsr.RRs в dns.RR
	for _, rr := range rrs {
		hdr := dns.RR_Header{Name: dns.Fqdn(rr.Name), Rrtype: dns.StringToType[rr.Type], Class: dns.ClassINET, Ttl: uint32(rr.TTL / time.Second)}
		switch rr.Type {
		case "A":
			ip := net.ParseIP(rr.Value)
			if ip == nil || ip.To4() == nil {
				continue
			}
			answers = append(answers, &dns.A{
				Hdr: hdr,
				A:   ip.To4(),
			})
		case "AAAA":
			ip := net.ParseIP(rr.Value)
			if ip == nil {
				log.Printf("Invalid AAAA record for %s: %s", q.Name, rr.Value)
				continue
			}
			if ip.To16() == nil || ip.To4() != nil {
				log.Printf("Invalid AAAA record for %s: %s", q.Name, rr.Value)
				continue
			}
			answers = append(answers, &dns.AAAA{
				Hdr:  hdr,
				AAAA: ip,
			})
		case "MX":
			// Предполагаем, что rr.Value содержит имя MX-сервера
			// Preference берём из дополнительной логики или используем значение по умолчанию
			answers = append(answers, &dns.MX{
				Hdr:        hdr,
				Preference: 10, // Значение по умолчанию, так как dnsr.RRs не предоставляет Preference
				Mx:         dns.Fqdn(rr.Value),
			})
		case "NS":
			answers = append(answers, &dns.NS{
				Hdr: hdr,
				Ns:  dns.Fqdn(rr.Value),
			})
		case "CNAME":
			answers = append(answers, &dns.CNAME{
				Hdr:    hdr,
				Target: dns.Fqdn(rr.Value),
			})
		case "TXT":
			answers = append(answers, &dns.TXT{
				Hdr: hdr,
				Txt: []string{rr.Value},
			})
		case "SOA":
			// Пропускаем SOA, так как они не запрашиваются напрямую
			continue
		default:
			log.Printf("Unsupported record type: %s for %s", rr.Type, rr.Name)
			continue
		}
	}

	log.Printf("Resolved %s %s: %d records", q.Name, qtype, len(answers))

	// Возвращаем ошибку, если не найдено записей для несуществующих доменов
	if len(answers) == 0 && len(rrs) == 0 {
		return nil, fmt.Errorf("no records found for %s %s", q.Name, qtype)
	}

	return answers, nil
}

func isLoopDetected(remoteIP net.IP) bool {
	// Проверяем, является ли удалённый IP-адрес локальным или адресом петли
	if remoteIP.IsLoopback() {
		return true
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

func sendErrorResponse(conn *net.UDPConn, remoteAddr *net.UDPAddr, msg *dns.Msg, rcode int) {
	responseMsg := new(dns.Msg)
	responseMsg.SetRcode(msg, rcode)
	responseMsg.Compress = false
	responseMsg.Id = msg.Id // Устанавливаем правильный ID
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
