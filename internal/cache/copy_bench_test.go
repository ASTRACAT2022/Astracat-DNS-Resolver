package cache

import (
	"testing"

	"github.com/miekg/dns"
)

func makeMsg(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{1, 2, 3, 4},
	})
	return msg
}

func BenchmarkMsgCopy(b *testing.B) {
	msg := makeMsg("example.org.")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = msg.Copy()
	}
}
