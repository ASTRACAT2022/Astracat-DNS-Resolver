package app

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"balancedns/internal/cache"
	"balancedns/internal/config"
	"balancedns/internal/hosts"
	"balancedns/internal/logx"
	"balancedns/internal/metrics"
	"balancedns/internal/plugin"
	"balancedns/internal/router"
	control "balancedns/internal/runtime"

	"github.com/miekg/dns"
)

type Server struct {
	cfg      *config.Config
	logger   *logx.Logger
	metrics  *metrics.Provider
	cache    *cache.Cache
	plugins  *plugin.Engine
	resolver *router.Resolver
	hosts    *hosts.Table
	acl      []*net.IPNet

	chain     []string
	blacklist blacklistIndex
	allowlist allowlistIndex

	// Мульти-тенантность: конфиги по токенам (config_id) для DoH NextDNS-стиля.
	tenants map[string]*tenantConfig

	// Лог DNS-запросов (для аналитики по-доменно).
	queryLog *QueryLogger

	supervisor *control.Supervisor
}

// tenantConfig — конфиг конкретного токена (config_id).
type tenantConfig struct {
	blacklist blacklistIndex
	allowlist allowlistIndex
	hosts     *hosts.Table
}

// tenantForPath возвращает конфиг по токену из пути (/{token}).
// Если токен не найден — возвращает nil (используется дефолтный конфиг).
func (s *Server) tenantForPath(path string) *tenantConfig {
	if s.tenants == nil {
		return nil
	}
	// Путь вида /{token} или /{token}/...
	token := strings.TrimPrefix(path, "/")
	if i := strings.Index(token, "/"); i >= 0 {
		token = token[:i]
	}
	if token == "" || token == "dns-query" {
		return nil
	}
	return s.tenants[token]
}

// SetTenant добавляет/обновляет конфиг токена.
func (s *Server) SetTenant(token string, blacklist blacklistIndex, hosts *hosts.Table) {
	if s.tenants == nil {
		s.tenants = make(map[string]*tenantConfig)
	}
	s.tenants[token] = &tenantConfig{blacklist: blacklist, hosts: hosts}
}

// SetTenantFull добавляет/обновляет конфиг токена с allowlist.
func (s *Server) SetTenantFull(token string, blacklist blacklistIndex, allowlist allowlistIndex, hosts *hosts.Table) {
	if s.tenants == nil {
		s.tenants = make(map[string]*tenantConfig)
	}
	s.tenants[token] = &tenantConfig{blacklist: blacklist, allowlist: allowlist, hosts: hosts}
}

// RemoveTenant удаляет конфиг токена.
func (s *Server) RemoveTenant(token string) {
	if s.tenants != nil {
		delete(s.tenants, token)
	}
}

// blacklistIndex — индекс чёрного списка для быстрого O(1) поиска.
// Точные совпадения — в map; wildcard/suffix-правила — в отдельном слайсе
// (их обычно немного). Это заменяет линейный скан всего списка на каждый запрос.
type blacklistIndex struct {
	exact    map[string]struct{}
	suffixes []string
}

func newBlacklistIndex() blacklistIndex {
	return blacklistIndex{exact: make(map[string]struct{})}
}

// allowlistIndex — индекс белого списка (исключений) для O(1) поиска.
// Домены из allowlist НЕ блокируются, даже если они в blacklist.
type allowlistIndex struct {
	exact map[string]struct{}
}

func newAllowlistIndex() allowlistIndex {
	return allowlistIndex{exact: make(map[string]struct{})}
}

// isAllowed возвращает true, если домен (или его родитель) в allowlist.
func (a allowlistIndex) isAllowed(name string) bool {
	if len(a.exact) == 0 {
		return false
	}
	// Проверяем сам домен и всех родителей (example.com, com).
	for {
		if _, ok := a.exact[name]; ok {
			return true
		}
		idx := strings.IndexByte(name, '.')
		if idx < 0 {
			return false
		}
		name = name[idx+1:]
	}
}

func New(cfg *config.Config) (*Server, error) {
	m := metrics.New()
	logger := logx.New(cfg.Logging.Level, cfg.Logging.LogQueries)

	resolver, err := router.NewResolver(cfg.Upstreams, m)
	if err != nil {
		return nil, err
	}

	var c *cache.Cache
	if cfg.Cache.Enabled {
		c = cache.NewWithMetrics(cfg.Cache.Capacity, cfg.Cache.MinTTLSeconds, cfg.Cache.MaxTTLSeconds, m)
	}

	var engine *plugin.Engine
	if cfg.Plugins.Enabled && len(cfg.Plugins.Entries) > 0 {
		engine, err = plugin.NewEngineWithMetrics(cfg.Plugins.Entries, time.Duration(cfg.Plugins.TimeoutMS)*time.Millisecond, m)
		if err != nil {
			return nil, err
		}
	}

	var hostTable *hosts.Table
	if cfg.Hosts.File != "" {
		hostTable, err = hosts.Load(cfg.Hosts.File, cfg.Hosts.TTL)
		if err != nil {
			return nil, err
		}
	}

	acl, err := parseACL(cfg.ACL)
	if err != nil {
		return nil, err
	}

	// Чёрный список: из файла (если задан) или из конфига.
	blacklist, err := loadBlacklist(cfg)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:       cfg,
		logger:    logger,
		metrics:   m,
		cache:     c,
		plugins:   engine,
		resolver:  resolver,
		hosts:     hostTable,
		acl:       acl,
		chain:     normalizeChain(cfg.Routing.Chain),
		blacklist: blacklist,
	}

	// Лог DNS-запросов (для аналитики по-доменно).
	if cfg.QueryLog != "" {
		ql, err := NewQueryLogger(cfg.QueryLog)
		if err != nil {
			return nil, err
		}
		s.queryLog = ql
		// Периодический flush буфера (не блокирует DNS).
		go ql.FlushLoop(2*time.Second, nil)
	}

	// Загружаем тенантов (мульти-тенантность DoH) из директории.
	if cfg.TenantsDir != "" {
		if err := s.loadTenants(cfg.TenantsDir); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// loadTenants загружает конфиги тенантов из директории.
// Файлы: {token}.blacklist (домены по одному на строку) и {token}.hosts (hosts-формат).
func (s *Server) loadTenants(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // директории нет — нет тенантов
		}
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".blacklist") {
			continue
		}
		token := strings.TrimSuffix(name, ".blacklist")
		blPath := filepath.Join(dir, name)
		hostsPath := filepath.Join(dir, token+".hosts")

		// Загружаем blacklist.
		data, err := os.ReadFile(blPath)
		if err != nil {
			continue
		}
		var domains []string
		for _, line := range strings.Split(string(data), "\n") {
			d := strings.TrimSpace(line)
			if d == "" || strings.HasPrefix(d, "#") {
				continue
			}
			domains = append(domains, d)
		}
		bl := parseBlacklist(domains)

		// Загружаем hosts (если есть).
		var hostTable *hosts.Table
		if _, err := os.Stat(hostsPath); err == nil {
			hostTable, _ = hosts.Load(hostsPath, 120)
		}

		// Загружаем allowlist (исключения) — файл {token}.allowlist.
		al := newAllowlistIndex()
		alPath := filepath.Join(dir, token+".allowlist")
		if alData, err := os.ReadFile(alPath); err == nil {
			for _, line := range strings.Split(string(alData), "\n") {
				d := strings.TrimSpace(line)
				if d == "" || strings.HasPrefix(d, "#") {
					continue
				}
				al.exact[d] = struct{}{}
			}
		}

		s.SetTenantFull(token, bl, al, hostTable)
		s.logger.Infof("tenant loaded: %s (%d domains, %d allowlist)", token, len(domains), len(al.exact))
	}
	return nil
}

// ReloadTenantsLoop периодически перечитывает директорию тенантов
// (чтобы blocklist обновлялся при изменении конфигов).
func (s *Server) ReloadTenantsLoop(interval time.Duration, stop <-chan struct{}) {
	if s.cfg.TenantsDir == "" {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := s.loadTenants(s.cfg.TenantsDir); err != nil {
				s.logger.Errorf("tenants reload failed: %v", err)
			}
		case <-stop:
			return
		}
	}
}

// loadBlacklist загружает чёрный список: из файла (по одному домену на строку)
// или из cfg.Blacklist.Domains. Файл эффективен для больших списков (100K+ доменов),
// т.к. не требует парсинга огромного Lua-конфига.
func loadBlacklist(cfg *config.Config) (blacklistIndex, error) {
	if cfg.Blacklist.File != "" {
		data, err := os.ReadFile(cfg.Blacklist.File)
		if err != nil {
			return blacklistIndex{}, fmt.Errorf("read blacklist file: %w", err)
		}
		lines := strings.Split(string(data), "\n")
		domains := make([]string, 0, len(lines))
		for _, line := range lines {
			d := strings.TrimSpace(line)
			if d == "" || strings.HasPrefix(d, "#") {
				continue
			}
			domains = append(domains, d)
		}
		return parseBlacklist(domains), nil
	}
	return parseBlacklist(cfg.Blacklist.Domains), nil
}

func (s *Server) Run(ctx context.Context) error {
	dnsMux := dns.NewServeMux()
	dnsMux.HandleFunc(".", s.handleDNS)

	// Периодическая перезагрузка тенантов (обновление blocklist при изменении конфигов).
	if s.cfg.TenantsDir != "" {
		go s.ReloadTenantsLoop(30*time.Second, ctx.Done())
	}

	components := []control.ComponentConfig{
		{
			Name:     "dns-udp",
			Required: true,
			Start:    s.runDNSComponent("udp", s.cfg.Listen.DNS, dnsMux),
		},
		{
			Name:     "dns-tcp",
			Required: true,
			Start:    s.runDNSComponent("tcp", s.cfg.Listen.DNS, dnsMux),
		},
		{
			Name:     "metrics-http",
			Required: true,
			Start:    s.runMetricsComponent(),
		},
	}

	if s.cfg.Listen.DoT != "" {
		components = append(components, control.ComponentConfig{
			Name:     "dns-dot",
			Required: true,
			Start:    s.runDoTComponent(dnsMux),
		})
	}
	if s.cfg.Listen.DoH != "" {
		components = append(components, control.ComponentConfig{
			Name:     "dns-doh",
			Required: true,
			Start:    s.runDoHComponent(),
		})
	}

	s.supervisor = control.New(s.logger, s.metrics, components, control.Options{
		RestartBackoff:      time.Duration(s.cfg.Control.RestartBackoffMS) * time.Millisecond,
		RestartMaxBackoff:   time.Duration(s.cfg.Control.RestartMaxBackoffMS) * time.Millisecond,
		MaxConsecutiveFails: s.cfg.Control.MaxConsecutiveFailure,
		MinStableRun:        time.Duration(s.cfg.Control.MinStableRunMS) * time.Millisecond,
	})

	s.logger.Infof("control plane started: components=%d", len(components))
	err := s.supervisor.Run(ctx)
	if err != nil {
		return err
	}
	s.logger.Infof("graceful shutdown completed")
	return nil
}

func (s *Server) runDNSComponent(network, addr string, handler dns.Handler) func(context.Context) error {
	return func(ctx context.Context) error {
		srv := &dns.Server{
			Addr:         addr,
			Net:          network,
			Handler:      handler,
			ReusePort:    s.cfg.Listen.ReusePort,
			ReuseAddr:    s.cfg.Listen.ReuseAddr,
			UDPSize:      s.cfg.Listen.UDPSize,
			ReadTimeout:  time.Duration(s.cfg.Listen.ReadTimeoutMS) * time.Millisecond,
			WriteTimeout: time.Duration(s.cfg.Listen.WriteTimeoutMS) * time.Millisecond,
		}

		go func() {
			<-ctx.Done()
			_ = srv.Shutdown()
		}()

		s.logger.Infof("%s component started on %s", network, addr)
		err := srv.ListenAndServe()
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("%s listener failed: %w", network, err)
	}
}

func (s *Server) runDoTComponent(handler dns.Handler) func(context.Context) error {
	return func(ctx context.Context) error {
		cert, err := tls.LoadX509KeyPair(s.cfg.Listen.TLSCertFile, s.cfg.Listen.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("load dot certificate: %w", err)
		}

		srv := &dns.Server{
			Addr:         s.cfg.Listen.DoT,
			Net:          "tcp-tls",
			Handler:      handler,
			ReadTimeout:  time.Duration(s.cfg.Listen.ReadTimeoutMS) * time.Millisecond,
			WriteTimeout: time.Duration(s.cfg.Listen.WriteTimeoutMS) * time.Millisecond,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
			},
		}

		go func() {
			<-ctx.Done()
			_ = srv.Shutdown()
		}()

		s.logger.Infof("dot component started on %s", s.cfg.Listen.DoT)
		err = srv.ListenAndServe()
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("dot listener failed: %w", err)
	}
}

func (s *Server) runDoHComponent() func(context.Context) error {
	return func(ctx context.Context) error {
		mux := http.NewServeMux()
		// Принимаем DoH на любом пути: и /dns-query, и /{token} (NextDNS-стиль).
		// Токен в пути не влияет на обработку — все запросы идут по конфигу ноды.
		mux.HandleFunc("/", s.handleDoH)

		server := &http.Server{
			Addr:         s.cfg.Listen.DoH,
			Handler:      mux,
			ReadTimeout:  time.Duration(s.cfg.Listen.ReadTimeoutMS) * time.Millisecond,
			WriteTimeout: time.Duration(s.cfg.Listen.WriteTimeoutMS) * time.Millisecond,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}

		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		}()

		s.logger.Infof("doh component started on %s%s", s.cfg.Listen.DoH, s.cfg.Listen.DoHPath)
		err := server.ListenAndServeTLS(s.cfg.Listen.TLSCertFile, s.cfg.Listen.TLSKeyFile)
		if ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("doh listener failed: %w", err)
	}
}

func (s *Server) runMetricsComponent() func(context.Context) error {
	return func(ctx context.Context) error {
		mux := http.NewServeMux()
		mux.Handle("/metrics", s.metrics.Handler())
		mux.HandleFunc("/healthz", s.handleHealthz)
		mux.HandleFunc("/readyz", s.handleReadyz)
		mux.HandleFunc("/statusz", s.handleStatusz)

		server := &http.Server{
			Addr:         s.cfg.Listen.Metrics,
			Handler:      mux,
			ReadTimeout:  time.Duration(s.cfg.Listen.ReadTimeoutMS) * time.Millisecond,
			WriteTimeout: time.Duration(s.cfg.Listen.WriteTimeoutMS) * time.Millisecond,
		}

		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		}()

		s.logger.Infof("metrics component started on %s", s.cfg.Listen.Metrics)
		err := server.ListenAndServe()
		if ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("metrics listener failed: %w", err)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	s.writeSupervisorStatus(w, s.supervisor.Healthy(true))
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	s.writeSupervisorStatus(w, s.supervisor.Healthy(true))
}

func (s *Server) handleStatusz(w http.ResponseWriter, _ *http.Request) {
	s.writeSupervisorStatus(w, true)
}

func (s *Server) writeSupervisorStatus(w http.ResponseWriter, healthy bool) {
	if s.supervisor == nil {
		http.Error(w, "supervisor not initialized", http.StatusServiceUnavailable)
		return
	}

	resp := struct {
		Status     string          `json:"status"`
		Timestamp  time.Time       `json:"timestamp"`
		Components []control.State `json:"components"`
	}{
		Status:     "ok",
		Timestamp:  time.Now().UTC(),
		Components: s.supervisor.Snapshot(),
	}
	w.Header().Set("Content-Type", "application/json")
	if !healthy {
		resp.Status = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Errorf("panic in dns handler: %v", r)
			// Best-effort SERVFAIL so the client gets a response instead of a hang.
			if req != nil {
				_ = w.WriteMsg(s.rcodeResponse(req, dns.RcodeServerFailure))
			}
		}
	}()
	resp := s.resolveDNS(req, w.RemoteAddr(), protocolFromNet(w.LocalAddr()), nil)
	if err := w.WriteMsg(resp); err != nil {
		s.logger.Errorf("write dns response: %v", err)
	}
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	remoteIP := remoteIPFromString(r.RemoteAddr)
	if !s.allowedRemoteIP(remoteIP) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	wire, err := readDoHWireMessage(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}

	resp := s.resolveDNS(req, &net.TCPAddr{IP: remoteIP}, "doh", s.tenantForPath(r.URL.Path))
	payload, err := resp.Pack()
	if err != nil {
		http.Error(w, "encode dns response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func readDoHWireMessage(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		encoded := strings.TrimSpace(r.URL.Query().Get("dns"))
		if encoded == "" {
			return nil, errors.New("missing dns query parameter")
		}
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("invalid dns query parameter")
		}
		return data, nil
	case http.MethodPost:
		defer r.Body.Close()
		data, err := io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			return nil, errors.New("failed to read request body")
		}
		if len(data) == 0 {
			return nil, errors.New("empty request body")
		}
		return data, nil
	default:
		return nil, errors.New("unsupported method")
	}
}

func (s *Server) resolveDNS(req *dns.Msg, remoteAddr net.Addr, protocol string, tenant *tenantConfig) *dns.Msg {
	protocol = metrics.ProtocolLabel(protocol)

	// Выбираем blacklist/hosts: tenant (по токену) или дефолтные.
	bl := s.blacklist
	hosts := s.hosts
	al := s.allowlist
	blocked := false
	if tenant != nil {
		bl = tenant.blacklist
		hosts = tenant.hosts
		al = tenant.allowlist
	}

	if len(req.Question) == 0 {
		s.metrics.IncQueries(protocol, "OTHER")
		s.metrics.IncResponse(metrics.RcodeLabel(dns.RcodeFormatError))
		return s.rcodeResponse(req, dns.RcodeFormatError)
	}

	if !s.allowedRemoteIP(remoteIPFromNetAddr(remoteAddr)) {
		s.metrics.IncQueries(protocol, metrics.QueryTypeLabel(req.Question[0].Qtype))
		s.metrics.IncResponse(metrics.RcodeLabel(dns.RcodeRefused))
		return s.rcodeResponse(req, dns.RcodeRefused)
	}

	current := normalizeQuestion(req.Question[0])
	qtypeLabel := metrics.QueryTypeLabel(current.Qtype)

	s.metrics.IncQueries(protocol, qtypeLabel)
	s.metrics.IncQueriesInFlight()
	defer s.metrics.DecQueriesInFlight()
	start := time.Now()

	remote := "<unknown>"
	if remoteAddr != nil {
		remote = remoteAddr.String()
	}
	s.logger.Queryf("query id=%d remote=%s domain=%s type=%s", req.Id, remote, current.Name, dns.TypeToString[current.Qtype])

	var resp *dns.Msg
	for _, stage := range s.chain {
		switch stage {
		case "blacklist":
			// Исключения (allowlist) имеют приоритет: если домен в allowlist — не блокируем.
			if al.isAllowed(current.Name) {
				s.logger.Debugf("allowlisted domain %s (skip blacklist)", current.Name)
				continue
			}
			if isBlockedIndex(bl, current.Name) {
				s.logger.Debugf("blocked domain %s", current.Name)
				blocked = true
				resp = s.rcodeResponse(req, dns.RcodeRefused)
				goto done
			}

		case "hosts":
			if hosts == nil {
				continue
			}
			if ans, ok := hosts.Lookup(current.Name, current.Qtype); ok {
				resp = s.localDataResponse(req, current, plugin.LocalData{IPs: ans.IPs, TTL: ans.TTL})
				goto done
			}

		case "cache":
			if s.cache == nil {
				continue
			}
			if cached, ok := s.cache.Get(current); ok {
				s.metrics.IncCacheHits()
				cached.Id = req.Id
				cached.Question = []dns.Question{current}
				resp = cached
				goto done
			}
			s.metrics.IncCacheMisses()

		case "lua_policy", "plugin", "plugins", "lua":
			if s.plugins == nil {
				continue
			}
			decision, err := s.plugins.Decide(current)
			if err != nil {
				s.logger.Errorf("plugin execution error for %s: %v", current.Name, err)
				continue
			}
			switch decision.Action {
			case plugin.ActionBlock:
				resp = s.rcodeResponse(req, dns.RcodeRefused)
				goto done
			case plugin.ActionLocalData:
				resp = s.localDataResponse(req, decision.Question, decision.Local)
				goto done
			case plugin.ActionRewrite, plugin.ActionForward:
				current = normalizeQuestion(decision.Question)
			}

		case "upstream":
			var fwdErr error
			resp, _, fwdErr = s.resolver.Forward(context.Background(), req, current)
			if fwdErr != nil {
				s.logger.Errorf("upstream forward failed for %s: %v", current.Name, fwdErr)
				resp = s.rcodeResponse(req, dns.RcodeServerFailure)
				goto done
			}
			if resp == nil {
				s.logger.Errorf("upstream returned nil response for %s", current.Name)
				resp = s.rcodeResponse(req, dns.RcodeServerFailure)
				goto done
			}
			if s.cache != nil && resp.Rcode == dns.RcodeSuccess {
				s.cache.Set(current, resp)
			}
			s.logger.Debugf("upstream served domain=%s type=%s", current.Name, dns.TypeToString[current.Qtype])
			goto done
		default:
			s.logger.Debugf("unknown chain stage: %s", stage)
		}
	}

	resp = s.rcodeResponse(req, dns.RcodeServerFailure)

done:
	if resp == nil {
		resp = s.rcodeResponse(req, dns.RcodeServerFailure)
	}
	s.metrics.ObserveQuery(protocol, qtypeLabel, metrics.RcodeLabel(resp.Rcode), time.Since(start))
	s.metrics.IncResponse(metrics.RcodeLabel(resp.Rcode))
	// Логируем запрос (асинхронно, не блокирует DNS-ответ) для аналитики по-доменно.
	if s.queryLog != nil {
		s.queryLog.Log(QueryLogEntry{
			ConfigID: s.tenantToken(tenant),
			Domain:   strings.TrimSuffix(current.Name, "."),
			Blocked:  blocked,
			Qtype:    dns.TypeToString[current.Qtype],
			Ts:       time.Now().UnixMilli(),
		})
	}
	return resp
}

// tenantToken возвращает config_id (токен) для tenant.
func (s *Server) tenantToken(tenant *tenantConfig) string {
	if tenant == nil {
		return ""
	}
	for token, t := range s.tenants {
		if t == tenant {
			return token
		}
	}
	return ""
}

func (s *Server) localDataResponse(req *dns.Msg, q dns.Question, local plugin.LocalData) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Question = []dns.Question{q}
	resp.Authoritative = true

	ttl := local.TTL
	if ttl == 0 {
		ttl = 60
	}

	for _, ip := range local.IPs {
		switch {
		case q.Qtype == dns.TypeA && ip.To4() != nil:
			resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: ip.To4()})
		case q.Qtype == dns.TypeAAAA && ip.To16() != nil && ip.To4() == nil:
			resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: ip.To16()})
		case q.Qtype == dns.TypeANY:
			if ip.To4() != nil {
				resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: ip.To4()})
			} else if ip.To16() != nil {
				resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: ip.To16()})
			}
		}
	}

	return resp
}

func (s *Server) isBlocked(name string) bool {
	return isBlockedIndex(s.blacklist, name)
}

// isBlockedIndex проверяет домен по конкретному индексу чёрного списка.
func isBlockedIndex(bl blacklistIndex, name string) bool {
	normalized := normalizeDomain(name)
	if _, ok := bl.exact[normalized]; ok {
		return true
	}
	for _, suffix := range bl.suffixes {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func (s *Server) rcodeResponse(req *dns.Msg, rcode int) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetRcode(req, rcode)
	return msg
}

func parseBlacklist(domains []string) blacklistIndex {
	idx := newBlacklistIndex()
	for _, d := range domains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			idx.suffixes = append(idx.suffixes, normalizeDomain(strings.TrimPrefix(d, "*")))
			continue
		}
		if strings.HasPrefix(d, ".") {
			idx.suffixes = append(idx.suffixes, normalizeDomain(d))
			continue
		}
		idx.exact[normalizeDomain(d)] = struct{}{}
	}
	return idx
}

func normalizeChain(chain []string) []string {
	out := make([]string, 0, len(chain))
	for _, stage := range chain {
		n := strings.TrimSpace(strings.ToLower(stage))
		if n != "" {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return []string{"blacklist", "hosts", "cache", "lua_policy", "upstream"}
	}
	return out
}

func normalizeQuestion(q dns.Question) dns.Question {
	q.Name = normalizeDomain(q.Name)
	if q.Qclass == 0 {
		q.Qclass = dns.ClassINET
	}
	return q
}

func normalizeDomain(name string) string {
	return strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
}

func parseACL(values []string) ([]*net.IPNet, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]*net.IPNet, 0, len(values))
	for i, value := range values {
		netmask, err := parseCIDROrIP(value)
		if err != nil {
			return nil, fmt.Errorf("acl[%d]: %w", i, err)
		}
		out = append(out, netmask)
	}
	return out, nil
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

func (s *Server) allowedRemoteIP(ip net.IP) bool {
	if len(s.acl) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, netmask := range s.acl {
		if netmask.Contains(ip) {
			return true
		}
	}
	return false
}

func protocolFromNet(addr net.Addr) string {
	if addr == nil {
		return "other"
	}
	switch addr.(type) {
	case *net.UDPAddr:
		return "udp"
	case *net.TCPAddr:
		return "tcp"
	default:
		return "other"
	}
}

func remoteIPFromNetAddr(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	default:
		return remoteIPFromString(addr.String())
	}
}

func remoteIPFromString(raw string) net.IP {
	host := strings.TrimSpace(raw)
	if host == "" {
		return nil
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host)
}
