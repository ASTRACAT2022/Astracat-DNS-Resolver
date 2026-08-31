package app

import (
	"testing"
)

func TestTenantForSNI(t *testing.T) {
	s := &Server{tenants: map[string]*tenantConfig{
		"ed2x":  {},
		"baa5aa": {},
		"de1906": {},
	}}

	cases := []struct {
		sni  string
		want string // ожидаемый config_id, "" = nil
	}{
		{"ed2x.dns.astracat.network", "ed2x"},
		{"baa5aa.dns.astracat.network", "baa5aa"},
		{"de1906.dns.astracat.network", "de1906"},
		{"dns.astracat.network", ""},          // без поддомена → nil
		{"ed2x.dns.astracat.network.", "ed2x"}, // с trailing dot
		{"unknown.dns.astracat.network", ""},   // неизвестный конфиг → nil
		{"", ""},                               // пустой SNI → nil
	}

	for _, c := range cases {
		got := s.tenantForSNI(c.sni)
		if c.want == "" {
			if got != nil {
				t.Errorf("tenantForSNI(%q): expected nil, got %v", c.sni, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("tenantForSNI(%q): expected tenant %q, got nil", c.sni, c.want)
			continue
		}
		// Проверяем, что это правильный конфиг (по адресу в map).
		if s.tenants[c.want] != got {
			t.Errorf("tenantForSNI(%q): expected %q, got different tenant", c.sni, c.want)
		}
	}
}
