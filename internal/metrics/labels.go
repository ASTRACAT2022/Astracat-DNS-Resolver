package metrics

import (
	"strings"

	"github.com/miekg/dns"
)

// Label normalization helpers. All labels are drawn from small, bounded sets
// to keep Prometheus cardinality low. Never pass raw domain names, client IPs,
// or query IDs here.

// QueryTypeLabel maps a DNS qtype to a bounded label value.
func QueryTypeLabel(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeCNAME:
		return "CNAME"
	case dns.TypeMX:
		return "MX"
	case dns.TypeNS:
		return "NS"
	case dns.TypeTXT:
		return "TXT"
	case dns.TypePTR:
		return "PTR"
	case dns.TypeSOA:
		return "SOA"
	case dns.TypeHTTPS:
		return "HTTPS"
	case dns.TypeSVCB:
		return "SVCB"
	default:
		return "OTHER"
	}
}

// RcodeLabel maps a DNS rcode to a bounded label value.
func RcodeLabel(rcode int) string {
	switch rcode {
	case dns.RcodeSuccess:
		return "NOERROR"
	case dns.RcodeNameError:
		return "NXDOMAIN"
	case dns.RcodeServerFailure:
		return "SERVFAIL"
	case dns.RcodeRefused:
		return "REFUSED"
	case dns.RcodeFormatError:
		return "FORMERR"
	default:
		return "OTHER"
	}
}

// ProtocolLabel normalizes a network/protocol string to a bounded label value.
func ProtocolLabel(network string) string {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "udp":
		return "udp"
	case "tcp":
		return "tcp"
	case "tcp-tls", "dot":
		return "dot"
	case "doh", "https":
		return "doh"
	default:
		return "other"
	}
}
