package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockResolver имитирует интерфейс DNSResolver для тестирования.
type mockResolver struct {
	AResponses    map[string][]net.IP
	CNAMEResponses map[string]string
	MXResponses    map[string][]*net.MX
	NSResponses    map[string][]*net.NS
	TXTResponses   map[string][]string
	error         error
}

func (m *mockResolver) LookupHost(host string) ([]net.IP, error) {
	if m.error != nil {
		return nil, m.error
	}
	if res, ok := m.AResponses[host]; ok {
		return res, nil
	}
	return nil, fmt.Errorf("no A record for %s", host)
}

func (m *mockResolver) LookupCNAME(host string) (string, error) {
	if m.error != nil {
		return "", m.error
	}
	if res, ok := m.CNAMEResponses[host]; ok {
		return res, nil
	}
	return "", fmt.Errorf("no CNAME record for %s", host)
}

func (m *mockResolver) LookupMX(host string) ([]*net.MX, error) {
	if m.error != nil {
		return nil, m.error
	}
	if res, ok := m.MXResponses[host]; ok {
		return res, nil
	}
	return nil, fmt.Errorf("no MX record for %s", host)
}

func (m *mockResolver) LookupNS(host string) ([]*net.NS, error) {
	if m.error != nil {
		return nil, m.error
	}
	if res, ok := m.NSResponses[host]; ok {
		return res, nil
	}
	return nil, fmt.Errorf("no NS record for %s", host)
}

func (m *mockResolver) LookupTXT(host string) ([]string, error) {
	if m.error != nil {
		return nil, m.error
	}
	if res, ok := m.TXTResponses[host]; ok {
		return res, nil
	}
	return nil, fmt.Errorf("no TXT record for %s", host)
}

func TestHandleRequest(t *testing.T) {
	mockResolver := &mockResolver{
		AResponses: map[string][]net.IP{
			"example.com.": {net.ParseIP("192.168.1.1")},
		},
		CNAMEResponses: map[string]string{
			"www.example.com.": "example.com.",
		},
		MXResponses: map[string][]*net.MX{
			"example.com.": {{Host: "mail.example.com.", Pref: 10}},
		},
		NSResponses: map[string][]*net.NS{
			"example.com.": {{Host: "ns1.example.com."}},
		},
		TXTResponses: map[string][]string{
			"example.com.": {"v=spf1 include:_spf.example.com ~all"},
		},
	}

	resolver = mockResolver // Устанавливаем наш mockResolver в качестве глобального резолвера

	// Создаем UDP-соединение для имитации запроса
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Не удалось разрешить UDP-адрес: %v", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatalf("Не удалось прослушать UDP: %v", err)
	}
	defer conn.Close()

	// Запускаем обработчик запросов в горутине
	
	go startDNSServer(conn)

	// Тестовый случай для A-записи
	msgA := new(dns.Msg)
	msgA.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	respA, err := sendDNSQuery(conn.LocalAddr().String(), msgA)
	if err != nil {
		t.Fatalf("Ошибка при отправке DNS-запроса для A-записи: %v", err)
	}
	if len(respA.Answer) == 0 {
		t.Errorf("Ожидался ответ для A-записи, но не получен")
	}
	if a, ok := respA.Answer[0].(*dns.A); ok {
		if a.A.String() != "192.168.1.1" {
			t.Errorf("Неверный IP-адрес для A-записи: ожидалось 192.168.1.1, получено %s", a.A.String())
		}
	} else {
		t.Errorf("Ожидался ответ типа A, получен %T", respA.Answer[0])
	}

	// Тестовый случай для CNAME-записи
	msgCNAME := new(dns.Msg)
	msgCNAME.SetQuestion(dns.Fqdn("www.example.com"), dns.TypeCNAME)
	respCNAME, err := sendDNSQuery(conn.LocalAddr().String(), msgCNAME)
	if err != nil {
		t.Fatalf("Ошибка при отправке DNS-запроса для CNAME-записи: %v", err)
	}
	if len(respCNAME.Answer) == 0 {
		t.Errorf("Ожидался ответ для CNAME-записи, но не получен")
	}
	if cname, ok := respCNAME.Answer[0].(*dns.CNAME); ok {
		if cname.Target != dns.Fqdn("example.com") {
			t.Errorf("Неверный CNAME-цель: ожидалось %s, получено %s", dns.Fqdn("example.com"), cname.Target)
		}
	} else {
		t.Errorf("Ожидался ответ типа CNAME, получен %T", respCNAME.Answer[0])
	}

	// Тестовый случай для MX-записи
	msgMX := new(dns.Msg)
	msgMX.SetQuestion(dns.Fqdn("example.com"), dns.TypeMX)
	respMX, err := sendDNSQuery(conn.LocalAddr().String(), msgMX)
	if err != nil {
		t.Fatalf("Ошибка при отправке DNS-запроса для MX-записи: %v", err)
	}
	if len(respMX.Answer) == 0 {
		t.Errorf("Ожидался ответ для MX-записи, но не получен")
	}
	if mx, ok := respMX.Answer[0].(*dns.MX); ok {
		if mx.Mx != dns.Fqdn("mail.example.com") || mx.Preference != 10 {
			t.Errorf("Неверная MX-запись: ожидалось mail.example.com с приоритетом 10, получено %s с приоритетом %d", mx.Mx, mx.Preference)
		}
	} else {
		t.Errorf("Ожидался ответ типа MX, получен %T", respMX.Answer[0])
	}

	// Тестовый случай для NS-записи
	msgNS := new(dns.Msg)
	msgNS.SetQuestion(dns.Fqdn("example.com"), dns.TypeNS)
	respNS, err := sendDNSQuery(conn.LocalAddr().String(), msgNS)
	if err != nil {
		t.Fatalf("Ошибка при отправке DNS-запроса для NS-записи: %v", err)
	}
	if len(respNS.Answer) == 0 {
		t.Errorf("Ожидался ответ для NS-записи, но не получен")
	}
	if ns, ok := respNS.Answer[0].(*dns.NS); ok {
		if ns.Ns != dns.Fqdn("ns1.example.com") {
			t.Errorf("Неверная NS-запись: ожидалось ns1.example.com, получено %s", ns.Ns)
		}
	} else {
		t.Errorf("Ожидался ответ типа NS, получен %T", respNS.Answer[0])
	}

	// Тестовый случай для TXT-записи
	msgTXT := new(dns.Msg)
	msgTXT.SetQuestion(dns.Fqdn("example.com"), dns.TypeTXT)
	respTXT, err := sendDNSQuery(conn.LocalAddr().String(), msgTXT)
	if err != nil {
		t.Fatalf("Ошибка при отправке DNS-запроса для TXT-записи: %v", err)
	}
	if len(respTXT.Answer) == 0 {
		t.Errorf("Ожидался ответ для TXT-записи, но не получен")
	}
	if txt, ok := respTXT.Answer[0].(*dns.TXT); ok {
		if len(txt.Txt) == 0 || txt.Txt[0] != "v=spf1 include:_spf.example.com ~all" {
			t.Errorf("Неверная TXT-запись: ожидалось 'v=spf1 include:_spf.example.com ~all', получено '%v'", txt.Txt)
		}
	} else {
		t.Errorf("Ожидался ответ типа TXT, получен %T", respTXT.Answer[0])
	}
}

// sendDNSQuery отправляет DNS-запрос и возвращает ответ
func sendDNSQuery(addr string, msg *dns.Msg) (*dns.Msg, error) {
	udp := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 2 * time.Second)
	defer cancel()

	r, _, err := udp.ExchangeContext(ctx, msg, addr)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func TestRecursiveLoopProtection(t *testing.T) {
	mockResolver := &mockResolver{
		AResponses: map[string][]net.IP{
			"localhost.": {net.ParseIP("127.0.0.1")},
		},
	}

	resolver = mockResolver // Устанавливаем наш mockResolver в качестве глобального резолвера

	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Не удалось разрешить UDP-адрес: %v", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatalf("Не удалось прослушать UDP: %v", err)
	}
	defer conn.Close()

	go startDNSServer(conn)

	msgA := new(dns.Msg)
	msgA.SetQuestion(dns.Fqdn("localhost"), dns.TypeA)
	respA, err := sendDNSQuery(conn.LocalAddr().String(), msgA)
	if err != nil {
		t.Fatalf("Ошибка при отправке DNS-запроса для A-записи: %v", err)
	}

	// Ожидаем ошибку, так как localhost должен быть заблокирован
	if respA.Rcode != dns.RcodeServerFailure && respA.Rcode != dns.RcodeNameError {
		t.Errorf("Ожидалась ошибка для localhost, получено %d", respA.Rcode)
	}
}