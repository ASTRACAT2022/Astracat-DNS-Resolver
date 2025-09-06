package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

// CacheEntry представляет запись в кэше
type CacheEntry struct {
	Msg      *dns.Msg
	ExpireAt int64 // Unix timestamp для быстрой работы
}

// ErrorStats статистика ошибок по доменам
type ErrorStats struct {
	errors map[string]int64
	mutex  sync.RWMutex
}

// DNSHandler обрабатывает DNS-запросы
type DNSHandler struct {
	resolver *resolver.Resolver
	
	// Кэш с быстрым доступом
	cache    sync.Map // map[string]*CacheEntry
	cacheTTL int64    // в секундах
	
	// Статистика ошибок
	errorStats *ErrorStats
	
	// Метрики
	totalQueries  int64
	cachedQueries int64
}

// NewDNSHandler создает новый обработчик DNS-запросов
func NewDNSHandler() *DNSHandler {
	handler := &DNSHandler{
		resolver: resolver.NewResolver(),
		cacheTTL: 300, // 5 минут по умолчанию
		errorStats: &ErrorStats{
			errors: make(map[string]int64),
		},
	}

	// Настройка резолвера
	resolver.Query = func(s string) {
		// Минимальное логирование upstream запросов
	}

	// Запускаем очистку кэша в отдельной горутине
	go handler.cleanupCache()
	
	// Запускаем вывод метрик
	go handler.printMetrics()
	
	// Запускаем вывод сводки ошибок
	go handler.printErrorSummary()

	return handler
}

// cleanupCache периодически очищает истекшие записи из кэша
func (h *DNSHandler) cleanupCache() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		now := time.Now().Unix()
		removed := 0
		
		h.cache.Range(func(key, value interface{}) bool {
			entry := value.(*CacheEntry)
			if now > entry.ExpireAt {
				h.cache.Delete(key)
				removed++
			}
			return true
		})
		
		if removed > 0 {
			log.Printf("Cache cleanup: removed %d expired entries", removed)
		}
	}
}

// printMetrics выводит метрики работы сервера
func (h *DNSHandler) printMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		total := atomic.LoadInt64(&h.totalQueries)
		cached := atomic.LoadInt64(&h.cachedQueries)
		
		cacheHitRate := float64(0)
		if total > 0 {
			cacheHitRate = float64(cached) / float64(total) * 100
		}
		
		log.Printf("METRICS - Total: %d, Cached: %d (%.2f%%)", total, cached, cacheHitRate)
	}
}

// printErrorSummary выводит сводку по ошибкам
func (h *DNSHandler) printErrorSummary() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C
		
		h.errorStats.mutex.Lock()
		if len(h.errorStats.errors) > 0 {
			log.Printf("ERROR SUMMARY - Top problematic domains:")
			// Создаем срез для сортировки
			type domainError struct {
				domain string
				count  int64
			}
			
			var errors []domainError
			for domain, count := range h.errorStats.errors {
				errors = append(errors, domainError{domain, count})
			}
			
			// Простая сортировка по количеству ошибок (первые 10)
			for i := 0; i < len(errors) && i < 10; i++ {
				for j := i + 1; j < len(errors); j++ {
					if errors[i].count < errors[j].count {
						errors[i], errors[j] = errors[j], errors[i]
					}
				}
			}
			
			for i := 0; i < len(errors) && i < 10; i++ {
				log.Printf("  %s: %d errors", errors[i].domain, errors[i].count)
			}
			
			// Очищаем статистику после вывода
			h.errorStats.errors = make(map[string]int64)
		}
		h.errorStats.mutex.Unlock()
	}
}

// getCacheKey создает ключ для кэширования
func (h *DNSHandler) getCacheKey(name string, qtype uint16) string {
	return name + "|" + fmt.Sprintf("%d", qtype)
}

// getCachedResponse пытается получить ответ из кэша
func (h *DNSHandler) getCachedResponse(key string, request *dns.Msg) *dns.Msg {
	value, exists := h.cache.Load(key)
	if !exists {
		return nil
	}

	entry := value.(*CacheEntry)
	now := time.Now().Unix()
	
	// Проверяем, не истекло ли время жизни
	if now > entry.ExpireAt {
		h.cache.Delete(key)
		return nil
	}

	// Создаем копию сообщения
	cachedMsg := entry.Msg.Copy()
	
	// Сохраняем оригинальный ID запроса
	cachedMsg.Id = request.Id
	
	// Копируем EDNS0 опции из оригинального запроса
	if edns0 := request.IsEdns0(); edns0 != nil {
		// Создаем новый OPT record
		newOpt := new(dns.OPT)
		newOpt.Hdr.Name = "."
		newOpt.Hdr.Rrtype = dns.TypeOPT
		newOpt.SetUDPSize(edns0.UDPSize())
		newOpt.SetDo(edns0.Do())
		
		// Добавляем OPT record в ответ
		cachedMsg.Extra = append(cachedMsg.Extra, newOpt)
	}
	
	// Обновляем TTL в записях
	timeLeft := entry.ExpireAt - now
	if timeLeft < 0 {
		timeLeft = 0
	}
	ttlSeconds := uint32(timeLeft)
	
	// Обновляем TTL для всех записей
	for _, rr := range cachedMsg.Answer {
		rr.Header().Ttl = ttlSeconds
	}
	for _, rr := range cachedMsg.Ns {
		rr.Header().Ttl = ttlSeconds
	}
	for _, rr := range cachedMsg.Extra {
		// Пропускаем OPT record
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttlSeconds
		}
	}
	
	atomic.AddInt64(&h.cachedQueries, 1)
	return cachedMsg
}

// cacheResponse сохраняет ответ в кэш
func (h *DNSHandler) cacheResponse(key string, msg *dns.Msg) {
	// Определяем минимальный TTL
	minTTL := h.cacheTTL
	
	// Для NXDOMAIN устанавливаем меньший TTL (например, 30 секунд)
	if msg.Rcode == dns.RcodeNameError {
		minTTL = 30 // NXDOMAIN кэшируем на 30 секунд
	} else {
		// Ищем минимальный TTL во всех секциях для успешных ответов
		sections := [][]dns.RR{msg.Answer, msg.Ns, msg.Extra}
		for _, section := range sections {
			for _, rr := range section {
				// Пропускаем OPT record при расчете TTL
				if rr.Header().Rrtype != dns.TypeOPT && int64(rr.Header().Ttl) < minTTL && rr.Header().Ttl > 0 {
					minTTL = int64(rr.Header().Ttl)
				}
			}
		}
	}
	
	// Создаем копию сообщения для кэширования (без ID и OPT)
	cachedMsg := msg.Copy()
	
	// Удаляем OPT record из кэшируемого сообщения
	extra := make([]dns.RR, 0, len(cachedMsg.Extra))
	for _, rr := range cachedMsg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	cachedMsg.Extra = extra
	
	// Сохраняем в кэш
	expireAt := time.Now().Unix() + minTTL
	h.cache.Store(key, &CacheEntry{
		Msg:      cachedMsg,
		ExpireAt: expireAt,
	})
}

// recordError записывает ошибку в статистику
func (h *DNSHandler) recordError(domain string) {
	h.errorStats.mutex.Lock()
	defer h.errorStats.mutex.Unlock()
	
	h.errorStats.errors[domain]++
}

// isNormalError проверяет, является ли ошибка "нормальной" (не требующей логирования)
func (h *DNSHandler) isNormalError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") || 
		   strings.Contains(errStr, "Refused") || 
		   strings.Contains(errStr, "connection refused") ||
		   strings.Contains(errStr, "i/o timeout")
}

// ServeDNS обрабатывает входящие DNS-запросы
func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddInt64(&h.totalQueries, 1)
	
	// Создаем ответное сообщение
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true

	// Проверяем, есть ли вопросы
	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		return
	}

	question := r.Question[0]
	domain := question.Name

	// Создаем ключ для кэша
	cacheKey := h.getCacheKey(domain, question.Qtype)

	// Проверяем кэш
	if cachedResponse := h.getCachedResponse(cacheKey, r); cachedResponse != nil {
		// Отправляем ответ из кэша
		w.WriteMsg(cachedResponse)
		return
	}

	// Создаем запрос для upstream-сервера
	upstreamMsg := new(dns.Msg)
	upstreamMsg.SetQuestion(domain, question.Qtype)
	
	// Проверяем, запрашивается ли DNSSEC
	if r.IsEdns0() != nil && r.IsEdns0().Do() {
		upstreamMsg.SetEdns0(4096, true)
	}

	// Выполняем запрос с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	result := h.resolver.Exchange(ctx, upstreamMsg)
	
	// Проверяем ошибки
	if result.Err != nil {
		// Записываем ошибку в статистику
		h.recordError(domain)
		
		// Логируем только "нестандартные" ошибки
		if !h.isNormalError(result.Err) {
			log.Printf("ERROR resolving %s: %v", domain, result.Err)
		}
		
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// Копируем данные из ответа
	if result.Msg != nil {
		m.Answer = result.Msg.Answer
		m.Ns = result.Msg.Ns
		m.Extra = result.Msg.Extra
		
		// Копируем важные флаги
		m.MsgHdr.AuthenticatedData = result.Msg.MsgHdr.AuthenticatedData
		m.MsgHdr.RecursionAvailable = result.Msg.MsgHdr.RecursionAvailable
		m.MsgHdr.Response = result.Msg.MsgHdr.Response
		m.MsgHdr.Authoritative = result.Msg.MsgHdr.Authoritative
		m.Rcode = result.Msg.Rcode
		
		// Копируем EDNS0 опции
		if edns0 := r.IsEdns0(); edns0 != nil {
			// Убеждаемся, что OPT record присутствует
			hasOpt := false
			for _, rr := range m.Extra {
				if rr.Header().Rrtype == dns.TypeOPT {
					hasOpt = true
					break
				}
			}
			
			if !hasOpt {
				// Создаем новый OPT record
				newOpt := new(dns.OPT)
				newOpt.Hdr.Name = "."
				newOpt.Hdr.Rrtype = dns.TypeOPT
				newOpt.SetUDPSize(edns0.UDPSize())
				newOpt.SetDo(edns0.Do())
				m.Extra = append(m.Extra, newOpt)
			}
		}
		
		// Сохраняем в кэш
		h.cacheResponse(cacheKey, result.Msg)
	}

	// Отправляем ответ
	w.WriteMsg(m)
}

func main() {
	// Увеличиваем количество потоков для лучшей производительности
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Создаем обработчик
	handler := NewDNSHandler()

	// Создаем DNS-сервер
	server := &dns.Server{
		Addr:    ":5353",
		Net:     "udp",
		Handler: handler,
		UDPSize: 65535,
	}

	// Также создаем TCP-сервер для больших ответов
	tcpServer := &dns.Server{
		Addr:    ":5353",
		Net:     "tcp",
		Handler: handler,
	}

	log.Println("Starting DNS server on :5353")
	log.Println("Features: Caching with DNSSEC support + Error statistics")
	log.Printf("CPUs: %d", runtime.NumCPU())

	// Запуск UDP сервера в отдельной горутине
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP server: %v", err)
		}
	}()

	// Запуск TCP сервера в отдельной горутине
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start TCP server: %v", err)
		}
	}()

	// Ожидание сигнала завершения
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down DNS server...")

	// Завершение работы серверов
	server.Shutdown()
	tcpServer.Shutdown()

	log.Println("DNS server stopped")
}
