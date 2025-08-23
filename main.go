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
	mu          sync.Mutex
}

func NewDNSServer() *DNSServer {
	return &DNSServer{
		resolver:    dnsr.NewResolver(dnsr.WithCache(10000), dnsr.WithExpiry()),
		rateLimiter: rate.NewLimiter(rate.Every(time.Second), 100), // 100 запросов в секунду
		visited:     make(map[string]struct{}),
	}
}

func (s *DNSServer) handleRequest(conn net.Conn) {
	defer conn.Close()

	// Установка таймаута для соединения
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ограничение скорости
	if err := s.rateLimiter.Wait(ctx); err != nil {
		fmt.Println("Превышен лимит скорости:", err)
		return
	}

	buffer := make([]byte, 1024) // Увеличенный размер буфера
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Printf("Ошибка чтения из соединения: %v\n", err)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(buffer[:n]); err != nil {
		fmt.Printf("Ошибка распаковки DNS-сообщения: %v\n", err)
		return
	}

	if len(msg.Question) == 0 {
		fmt.Println("Нет вопросов в DNS-запросе")
		return
	}

	question := msg.Question[0]
	queryKey := fmt.Sprintf("%s:%d", question.Name, question.Qtype)

	// Проверка на рекурсивные циклы
	s.mu.Lock()
	if _, exists := s.visited[queryKey]; exists {
		s.mu.Unlock()
		fmt.Printf("Обнаружен потенциальный цикл для запроса: %s\n", queryKey)
		s.sendErrorResponse(conn, msg, dns.RcodeRefused)
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
		s.sendErrorResponse(conn, msg, dns.RcodeServerFailure)
		return
	default:
		qtypeStr, ok := dns.TypeToString[question.Qtype]
		if !ok {
			s.sendErrorResponse(conn, msg, dns.RcodeNotImplemented)
			return
		}

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

	out, err := reply.Pack()
	if err != nil {
		fmt.Printf("Ошибка упаковки DNS-ответа: %v\n", err)
		s.sendErrorResponse(conn, msg, dns.RcodeServerFailure)
		return
	}

	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		fmt.Printf("Ошибка установки дедлайна записи: %v\n", err)
		return
	}

	if _, err := conn.Write(out); err != nil {
		fmt.Printf("Ошибка записи в соединение: %v\n", err)
		return
	}
}

func (s *DNSServer) sendErrorResponse(conn net.Conn, msg *dns.Msg, rcode int) {
	reply := new(dns.Msg)
	reply.SetReply(msg)
	reply.Compress = true
	reply.SetRcode(msg, rcode)

	out, err := reply.Pack()
	if err != nil {
		fmt.Printf("Ошибка упаковки ответа об ошибке: %v\n", err)
		return
	}

	if _, err := conn.Write(out); err != nil {
		fmt.Printf("Ошибка записи ответа об ошибке: %v\n", err)
	}
}

func main() {
	server := NewDNSServer()
	listener, err := net.Listen("tcp", ":5454")
	if err != nil {
		fmt.Printf("Ошибка запуска сервера: %v\n", err)
		return
	}
	defer listener.Close()
	fmt.Println("DNS-резолвер слушает на порту 5454")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Ошибка принятия соединения: %v\n", err)
			continue
		}
		go server.handleRequest(conn)
	}
}
