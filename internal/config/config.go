package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Listen    ListenConfig    `json:"listen" yaml:"listen"`
	Logging   LoggingConfig   `json:"logging" yaml:"logging"`
	ACL       []string        `json:"acl" yaml:"acl"`
	Upstreams []Upstream      `json:"upstreams" yaml:"upstreams"`
	Routing   RoutingConfig   `json:"routing" yaml:"routing"`
	Cache     CacheConfig     `json:"cache" yaml:"cache"`
	Hosts     HostsConfig     `json:"hosts" yaml:"hosts"`
	Plugins   PluginConfig    `json:"plugins" yaml:"plugins"`
	Blacklist BlacklistConfig `json:"blacklist" yaml:"blacklist"`
	Control   ControlConfig   `json:"control" yaml:"control"`
	// TenantsDir — директория с конфигами тенантов (мульти-тенантность DoH).
	// Файлы: {token}.blacklist и {token}.hosts.
	TenantsDir string `json:"tenants_dir" yaml:"tenants_dir"`
	// QueryLog — путь к файлу лога DNS-запросов (JSON lines, для аналитики).
	QueryLog string `json:"query_log" yaml:"query_log"`
}

type ListenConfig struct {
	DNS            string `json:"dns" yaml:"dns"`
	DoT            string `json:"dot" yaml:"dot"`
	DoH            string `json:"doh" yaml:"doh"`
	DoHPath        string `json:"doh_path" yaml:"doh_path"`
	TLSCertFile    string `json:"tls_cert_file" yaml:"tls_cert_file"`
	TLSKeyFile     string `json:"tls_key_file" yaml:"tls_key_file"`
	Metrics        string `json:"metrics" yaml:"metrics"`
	ReadTimeoutMS  int    `json:"read_timeout_ms" yaml:"read_timeout_ms"`
	WriteTimeoutMS int    `json:"write_timeout_ms" yaml:"write_timeout_ms"`
	ReusePort      bool   `json:"reuse_port" yaml:"reuse_port"`
	ReuseAddr      bool   `json:"reuse_addr" yaml:"reuse_addr"`
	UDPSize        int    `json:"udp_size" yaml:"udp_size"`
}

type LoggingConfig struct {
	Level      string `json:"level" yaml:"level"`
	LogQueries bool   `json:"log_queries" yaml:"log_queries"`
}

type Upstream struct {
	Name                  string   `json:"name" yaml:"name"`
	Protocol              string   `json:"protocol" yaml:"protocol"`
	Addr                  string   `json:"addr" yaml:"addr"`
	DoHURL                string   `json:"doh_url" yaml:"doh_url"`
	TLSServerName         string   `json:"tls_server_name" yaml:"tls_server_name"`
	TLSInsecureSkipVerify bool     `json:"tls_insecure_skip_verify" yaml:"tls_insecure_skip_verify"`
	Zones                 []string `json:"zones" yaml:"zones"`
	TimeoutMS             int      `json:"timeout_ms" yaml:"timeout_ms"`
}

type RoutingConfig struct {
	Chain []string `json:"chain" yaml:"chain"`
}

type CacheConfig struct {
	Enabled       bool   `json:"enabled" yaml:"enabled"`
	Capacity      int    `json:"capacity" yaml:"capacity"`
	MinTTLSeconds uint32 `json:"min_ttl_seconds" yaml:"min_ttl_seconds"`
	MaxTTLSeconds uint32 `json:"max_ttl_seconds" yaml:"max_ttl_seconds"`
}

type HostsConfig struct {
	File string `json:"file" yaml:"file"`
	TTL  uint32 `json:"ttl" yaml:"ttl"`
}

type PluginConfig struct {
	Enabled   bool          `json:"enabled" yaml:"enabled"`
	TimeoutMS int           `json:"timeout_ms" yaml:"timeout_ms"`
	Scripts   []string      `json:"scripts" yaml:"scripts"`
	Entries   []PluginEntry `json:"entries" yaml:"entries"`
}

type PluginEntry struct {
	Name      string   `json:"name" yaml:"name"`
	Runtime   string   `json:"runtime" yaml:"runtime"`
	Path      string   `json:"path" yaml:"path"`
	Args      []string `json:"args" yaml:"args"`
	TimeoutMS int      `json:"timeout_ms" yaml:"timeout_ms"`
}

type BlacklistConfig struct {
	Domains []string `json:"domains" yaml:"domains"`
	// File — путь к файлу чёрного списка (по одному домену на строку).
	// Если задан, загружается из файла (эффективно для больших списков),
	// иначе — из Domains.
	File string `json:"file" yaml:"file"`
}

type ControlConfig struct {
	RestartBackoffMS      int `json:"restart_backoff_ms" yaml:"restart_backoff_ms"`
	RestartMaxBackoffMS   int `json:"restart_max_backoff_ms" yaml:"restart_max_backoff_ms"`
	MaxConsecutiveFailure int `json:"max_consecutive_failure" yaml:"max_consecutive_failure"`
	MinStableRunMS        int `json:"min_stable_run_ms" yaml:"min_stable_run_ms"`
}

func Load(path string) (*Config, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".lua" {
		return nil, errors.New("only Lua config is supported (.lua)")
	}

	cfg, err := loadLua(path)
	if err != nil {
		return nil, err
	}
	applyDefaults(cfg)
	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Listen.DNS == "" {
		cfg.Listen.DNS = ":53"
	}
	if cfg.Listen.Metrics == "" {
		cfg.Listen.Metrics = ":9090"
	}
	if cfg.Listen.DoH != "" && cfg.Listen.DoHPath == "" {
		cfg.Listen.DoHPath = "/dns-query"
	}
	if cfg.Listen.ReadTimeoutMS <= 0 {
		cfg.Listen.ReadTimeoutMS = 2000
	}
	if cfg.Listen.WriteTimeoutMS <= 0 {
		cfg.Listen.WriteTimeoutMS = 2000
	}
	if cfg.Listen.UDPSize <= 0 {
		cfg.Listen.UDPSize = 1232
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if len(cfg.Routing.Chain) == 0 {
		cfg.Routing.Chain = []string{"blacklist", "hosts", "cache", "lua_policy", "upstream"}
	}
	if cfg.Cache.Capacity == 0 {
		cfg.Cache.Capacity = 10000
	}
	if cfg.Cache.MinTTLSeconds == 0 {
		cfg.Cache.MinTTLSeconds = 5
	}
	if cfg.Cache.MaxTTLSeconds == 0 {
		cfg.Cache.MaxTTLSeconds = 3600
	}
	if cfg.Plugins.TimeoutMS == 0 {
		cfg.Plugins.TimeoutMS = 20
	}
	if cfg.Hosts.File != "" && cfg.Hosts.TTL == 0 {
		cfg.Hosts.TTL = 60
	}
	if cfg.Control.RestartBackoffMS <= 0 {
		cfg.Control.RestartBackoffMS = 200
	}
	if cfg.Control.RestartMaxBackoffMS <= 0 {
		cfg.Control.RestartMaxBackoffMS = 5000
	}
	if cfg.Control.MinStableRunMS <= 0 {
		cfg.Control.MinStableRunMS = 10000
	}

	if len(cfg.Plugins.Entries) == 0 && len(cfg.Plugins.Scripts) > 0 {
		cfg.Plugins.Entries = make([]PluginEntry, 0, len(cfg.Plugins.Scripts))
		for _, s := range cfg.Plugins.Scripts {
			cfg.Plugins.Entries = append(cfg.Plugins.Entries, PluginEntry{
				Name:    filepath.Base(s),
				Runtime: "lua",
				Path:    s,
			})
		}
	}

	for i := range cfg.Upstreams {
		if cfg.Upstreams[i].Protocol == "" {
			cfg.Upstreams[i].Protocol = "udp"
		}
		cfg.Upstreams[i].Protocol = strings.ToLower(strings.TrimSpace(cfg.Upstreams[i].Protocol))
		if cfg.Upstreams[i].TimeoutMS <= 0 {
			cfg.Upstreams[i].TimeoutMS = int((2 * time.Second).Milliseconds())
		}
	}

	for i := range cfg.Plugins.Entries {
		if cfg.Plugins.Entries[i].Runtime == "" {
			cfg.Plugins.Entries[i].Runtime = "lua"
		}
		cfg.Plugins.Entries[i].Runtime = strings.ToLower(strings.TrimSpace(cfg.Plugins.Entries[i].Runtime))
		if cfg.Plugins.Entries[i].Name == "" {
			cfg.Plugins.Entries[i].Name = filepath.Base(cfg.Plugins.Entries[i].Path)
		}
	}
}

func validate(cfg *Config) error {
	if len(cfg.Upstreams) == 0 {
		return errors.New("at least one upstream is required")
	}
	for _, up := range cfg.Upstreams {
		if up.Name == "" {
			return errors.New("upstream name is required")
		}
		switch up.Protocol {
		case "udp", "tcp", "dot":
			if up.Addr == "" {
				return fmt.Errorf("upstream %q address is required", up.Name)
			}
			if _, _, err := net.SplitHostPort(up.Addr); err != nil {
				return fmt.Errorf("upstream %q addr must be host:port", up.Name)
			}
		case "doh":
			if up.DoHURL == "" {
				return fmt.Errorf("upstream %q doh_url is required for protocol doh", up.Name)
			}
			u, err := url.Parse(up.DoHURL)
			if err != nil || u.Scheme != "https" {
				return fmt.Errorf("upstream %q doh_url must be valid https url", up.Name)
			}
		default:
			return fmt.Errorf("upstream %q has unsupported protocol %q", up.Name, up.Protocol)
		}
	}
	if err := validateListenAddr("listen.dns", cfg.Listen.DNS); err != nil {
		return err
	}
	if err := validateListenAddr("listen.metrics", cfg.Listen.Metrics); err != nil {
		return err
	}
	if cfg.Listen.DoT != "" {
		if err := validateListenAddr("listen.dot", cfg.Listen.DoT); err != nil {
			return err
		}
	}
	if cfg.Listen.DoH != "" {
		if err := validateListenAddr("listen.doh", cfg.Listen.DoH); err != nil {
			return err
		}
		if cfg.Listen.DoHPath == "" {
			return errors.New("listen.doh_path is required when listen.doh is set")
		}
		if !strings.HasPrefix(cfg.Listen.DoHPath, "/") {
			return errors.New("listen.doh_path must start with '/'")
		}
	}
	if cfg.Listen.DoT != "" || cfg.Listen.DoH != "" {
		if strings.TrimSpace(cfg.Listen.TLSCertFile) == "" || strings.TrimSpace(cfg.Listen.TLSKeyFile) == "" {
			return errors.New("listen.tls_cert_file and listen.tls_key_file are required for DoT/DoH listeners")
		}
	}

	for i, cidr := range cfg.ACL {
		if _, err := parseCIDROrIP(cidr); err != nil {
			return fmt.Errorf("acl[%d]: %w", i, err)
		}
	}

	if cfg.Cache.Capacity <= 0 {
		return errors.New("cache.capacity must be > 0")
	}
	if cfg.Listen.ReadTimeoutMS <= 0 || cfg.Listen.WriteTimeoutMS <= 0 {
		return errors.New("listen.read_timeout_ms and listen.write_timeout_ms must be > 0")
	}
	if cfg.Listen.UDPSize < 512 || cfg.Listen.UDPSize > 65535 {
		return errors.New("listen.udp_size must be in range [512, 65535]")
	}
	if cfg.Control.RestartBackoffMS <= 0 || cfg.Control.RestartMaxBackoffMS <= 0 {
		return errors.New("control.restart_backoff_ms and control.restart_max_backoff_ms must be > 0")
	}
	if cfg.Control.RestartBackoffMS > cfg.Control.RestartMaxBackoffMS {
		return errors.New("control.restart_backoff_ms must be <= control.restart_max_backoff_ms")
	}
	if cfg.Control.MaxConsecutiveFailure < 0 {
		return errors.New("control.max_consecutive_failure must be >= 0")
	}
	if cfg.Control.MinStableRunMS <= 0 {
		return errors.New("control.min_stable_run_ms must be > 0")
	}
	if cfg.Cache.MinTTLSeconds > cfg.Cache.MaxTTLSeconds {
		return errors.New("cache.min_ttl_seconds must be <= cache.max_ttl_seconds")
	}
	if cfg.Plugins.TimeoutMS <= 0 {
		return errors.New("plugins.timeout_ms must be > 0")
	}
	if cfg.Hosts.File != "" && cfg.Hosts.TTL == 0 {
		return errors.New("hosts.ttl must be > 0")
	}
	for i, p := range cfg.Plugins.Entries {
		if p.Path == "" {
			return fmt.Errorf("plugins.entries[%d].path is required", i)
		}
		switch p.Runtime {
		case "lua", "go_exec":
		default:
			return fmt.Errorf("plugins.entries[%d] has unsupported runtime %q", i, p.Runtime)
		}
		if p.TimeoutMS < 0 {
			return fmt.Errorf("plugins.entries[%d].timeout_ms must be >= 0", i)
		}
	}
	return nil
}

func validateListenAddr(field, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return fmt.Errorf("%s is required", field)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s must be host:port: %w", field, err)
	}
	if host != "" && net.ParseIP(host) == nil {
		return fmt.Errorf("%s host must be an IP address or empty (got %q)", field, host)
	}
	if strings.TrimSpace(port) == "" {
		return fmt.Errorf("%s port is required", field)
	}
	return nil
}

func parseCIDROrIP(value string) (*net.IPNet, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil, errors.New("empty ACL value")
	}
	if _, ipnet, err := net.ParseCIDR(v); err == nil {
		return ipnet, nil
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return nil, fmt.Errorf("invalid CIDR/IP %q", value)
	}
	if ip.To4() != nil {
		_, ipnet, _ := net.ParseCIDR(ip.String() + "/32")
		return ipnet, nil
	}
	_, ipnet, _ := net.ParseCIDR(ip.String() + "/128")
	return ipnet, nil
}
