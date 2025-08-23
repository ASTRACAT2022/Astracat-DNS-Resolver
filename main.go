package main

import (
	"context"
	"fmt"
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
	mu          sync.Mutex
}

func NewDNSServer() *DNSServer {
	// Инициализация резолвера с кэшем и истечением TTL
	return &DNSServer{
		resolver:    dnsr.NewResolver(dnsr.WithCache(10000), dnsr.WithExpiry()),
		rateLimiter: rate.NewLimiter(rate.Every(time.Second), 100), // 100 запросов в секунду
		visited:     make(map[string]struct{}),
	}
}

func (s *DNSServer) handleRequest(w dns.ResponseWriter, msg *dns.Msg) {
	// Установка таймаута для соединения
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ограничение скорости
	if err := s.rateLimiter.Wait(ctx); err != nil {
		fmt.Println("Превышен лимит скорости:", err)
		s.sendErrorResponse(w, msg, dns.RcodeServerFailure)
		return
	}

	if len(msg.Question) == 0 {
		fmt.Println("Нет вопросов в DNS-запросе")
		s.sendErrorResponse(w, msg, dns.RcodeFormatError)
		return
	}

	question := msg.Question[0]
	queryKey := fmt.Sprintf("%s:%d", question.Name, question.Qtype)

	// Проверка на рекурсивные циклы
	s.mu.Lock()
	if _, exists := s.visited[queryKey]; exists {
		s.mu.Unlock()
		fmt.Printf("Обнаружен потенциальный цикл для запроса: %s\n", queryKey)
		s.sendErrorResponse(w, msg, dns.RcodeRefused)
		return
	}
	s.visited[queryKey] = struct{}{}
	s.mu.Unlock()

	// Периодическая очистка карты visited
	if len(s.visited) > 10000 {
		s.mu.Lock()
		s.visited = make(map[string]struct{})
		s.mu.Unlock()
	}

	fmt.Printf("Получен запрос для %s (Тип %s)\n", question.Name, dns.Type(question.Qtype).String())

	reply := new(dns.Msg)
	reply.SetReply(msg)
	reply.Compress = true
	reply.RecursionAvailable = true

	// Обработка запроса с таймаутом контекста
	queryCtx, queryCancel := context.WithTimeout(ctx, 3*time.Second)
	defer queryCancel()

	select {
	case <-queryCtx.Done():
		fmt.Println("Таймаут запроса")
		s.sendErrorResponse(w, msg, dns.RcodeServerFailure)
		return
	default:
		qtypeStr, ok := dns.TypeToString[question.Qtype]
		if !ok {
			s.sendErrorResponse(w, msg, dns.RcodeNotImplemented)
			return
		}

		// Рекурсивное разрешение через корневые серверы с помощью dnsr
		results := s.resolver.Resolve(question.Name, qtypeStr)
		for _, res := range results {
			rrStr := res.String()
			rr, err := dns.NewRR(rrStr)
			if err == nil {
				reply.Answer = append(reply.Answer, rr)
			} else {
				fmt.Printf("Ошибка конвертации RR: %v для %s\n", err, rrStr)
			}
		}
		if len(results) == 0 {
			reply.SetRcode(msg, dns.RcodeNameError)
		}
	}

	// Удаление из visited после обработки
	s.mu.Lock()
	delete(s.visited, queryKey)
	s.mu.Unlock()

	if err := w.WriteMsg(reply); err != nil {
		fmt.Printf("Ошибка отправки ответа: %v\n", err)
	}
}

func (s *DNSServer) sendErrorResponse(w dns.ResponseWriter, msg *dns.Msg, rcode int) {
	reply := new(dns.Msg) // Исправлено: использование new(dns.Msg) вместо newល
	reply.SetReply(msg)
	reply.Compress = true
	reply.SetRcode(msg, rcode)

	if err := w.WriteMsg(reply); err != nil {
		fmt.Printf("Ошибка отправки ответа об ошибке: %v\n", err)
	}
}

func main() {
	server := NewDNSServer()

	// Запуск UDP-сервера
	udpServer := &dns.Server{Addr: ":5454", Net: "udp"}
	dns.HandleFunc(".", server.handleRequest)

	go func() {
		fmt.Println("DNS-резолвер (UDP) слушает на порту 5454")
		if err := udpServer.ListenAndServe(); err != nil {
			fmt.Printf("Ошибка запуска UDP-сервера: %v\n", err)
		}
	}()

	// Запуск TCP-сервера
	tcpServer := &dns.Server{Addr: ":5454", Net: "tcp"}
	go func() {
		fmt.Println("DNS-резолвер (TCP) слушает на порту 5454")
		if err := tcpServer.ListenAndServe(); err != nil {
			fmt.Printf("Ошибка запуска TCP-сервера: %v\n", err)
		}
	}()

	// Блокировка для поддержания работы сервера
	select {}
}
