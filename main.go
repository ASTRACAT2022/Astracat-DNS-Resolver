package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
	"net"
	"net/http"
	"runtime"
)

// CacheEntry хранит DNS-ответ и время истечения
type CacheEntry struct {
	Answer     *dns.Msg
	Expiration time.Time
}

// Resolver структура для рекурсивного DNS-резолвера
type Resolver struct {
	cache        *ristretto.Cache
	client       *dns.Client
	queryCount   *prometheus.CounterVec
	cacheHits    prometheus.Counter
	cacheMisses  prometheus.Counter
	queryTime    *prometheus.HistogramVec
	iterations   *prometheus.CounterVec
	cnameFollows prometheus.Counter
	rootServers  []string
	workerPool   *semaphore.Weighted
	connPool     *sync.Pool
}

// NewResolver создает новый рекурсивный резолвер
func NewResolver() (*Resolver, error) {
	// Инициализация кэша с ristretto
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,     // Поддержка до 10M ключей
		MaxCost:     1 << 30, // 1GB памяти для кэша
		BufferItems: 64,      // Оптимизация для высоких нагрузок
		Metrics:     true,    // Включение метрик кэша
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Корневые серверы (полный список от IANA)
	rootServers := []string{
		"198.41.0.4:53",    // a.root-servers.net
		"199.9.14.201:53",  // b.root-servers.net
		"192.33.4.12:53",   // c.root-servers.net
		"199.7.91.13:53",   // d.root-servers.net
		"192.203.230.10:53", // e.root-servers.net
		"192.5.5.241:53",   // f.root-servers.net
		"192.112.36.4:53",  // g.root-servers.net
		"198.97.190.53:53", // h.root-servers.net
		"192.36.148.17:53", // i.root-servers.net
		"192.58.128.30:53", // j.root-servers.net
		"193.0.14.129:53",  // k.root-servers.net
		"199.7.83.42:53",   // l.root-servers.net
		"202.12.27.33:53",  // m.root-servers.net
	}

	queryCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_queries_total",
			Help: "Total number of DNS queries",
		},
		[]string{"type"},
	)
	cacheHits := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_cache_hits_total",
			Help: "Total number of cache hits",
		},
	)
	cacheMisses := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_cache_misses_total",
			Help: "Total number of cache misses",
		},
	)
	queryTime := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dns_query_duration_seconds",
			Help:    "DNS query duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"type"},
	)
	iterations := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_resolution_iterations_total",
			Help: "Total number of iterations for recursive resolution",
		},
		[]string{"domain"},
	)
	cnameFollows := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_cname_follows_total",
			Help: "Total number of CNAME records followed",
		},
	)

	prometheus.MustRegister(queryCount, cacheHits, cacheMisses, queryTime, iterations, cnameFollows)

	// Пул соединений для повторного использования
	connPool := &sync.Pool{
		New: func() interface{} {
			conn, err := net.Dial("udp", "0.0.0.0:0")
			if err != nil {
				log.Error().Err(err).Msg("Failed to create UDP connection")
				return nil
			}
			return conn
		},
	}

	return &Resolver{
		cache:        cache,
		client:       &dns.Client{Net: "udp", Timeout: 1 * time.Second, SingleInflight: true},
		queryCount:   queryCount,
		cacheHits:    cacheHits,
		cacheMisses:  cacheMisses,
		queryTime:    queryTime,
		iterations:   iterations,
		cnameFollows: cnameFollows,
		rootServers:  rootServers,
		workerPool:   semaphore.NewWeighted(int64(2 * runtime.NumCPU())),
		connPool:     connPool,
	}, nil
}

// cleanCache периодически очищает устаревшие записи кэша
func (r *Resolver) cleanCache(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Stopping cache cleaner")
			return
		case <-ticker.C:
			r.cache.Clear()
			log.Info().Msg("Cleared expired cache entries")
		}
	}
}

// HandleDNS обрабатывает входящие DNS-запросы
func (r *Resolver) HandleDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	queryType := dns.TypeToString[req.Question[0].Qtype]
	r.queryCount.WithLabelValues(queryType).Inc()

	// Добавляем EDNS0 для поддержки DNSSEC и больших ответов
	req.SetEdns0(4096, true)

	// Проверяем кэш
	cacheKey := fmt.Sprintf("%s:%d", req.Question[0].Name, req.Question[0].Qtype)
	if value, ok := r.cache.Get(cacheKey); ok {
		if cached, ok := value.(CacheEntry); ok && time.Now().Before(cached.Expiration) {
			cached.Answer.Id = req.Id
			r.cacheHits.Inc()
			log.Info().Str("domain", req.Question[0].Name).Str("type", queryType).Msg("Cache hit")
			w.WriteMsg(cached.Answer)
			return
		}
	}

	r.cacheMisses.Inc()
	log.Info().Str("domain", req.Question[0].Name).Str("type", queryType).Msg("Cache miss")

	// Ограничиваем количество одновременных запросов
	ctx := context.Background()
	if err := r.workerPool.Acquire(ctx, 1); err != nil {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		log.Error().Err(err).Str("domain", req.Question[0].Name).Msg("Worker pool limit reached")
		w.WriteMsg(resp)
		return
	}
	defer r.workerPool.Release(1)

	// Рекурсивное разрешение
	resp, err := r.resolve(req)
	if err != nil {
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		log.Error().Err(err).Str("domain", req.Question[0].Name).Msg("Resolution failed")
	}

	r.queryTime.WithLabelValues(queryType).Observe(time.Since(start).Seconds())
	w.WriteMsg(resp)
}

// resolve выполняет рекурсивное разрешение DNS
func (r *Resolver) resolve(req *dns.Msg) (*dns.Msg, error) {
	domain := req.Question[0].Name
	qtype := req.Question[0].Qtype
	iteration := 0
	maxIterations := 20

	currentServers := r.rootServers
	seenDomains := make(map[string]struct{})
	seenDomains[domain] = struct{}{}

	for iteration < maxIterations {
		iteration++
		r.iterations.WithLabelValues(domain).Inc()

		// Проверяем кэш
		cacheKey := fmt.Sprintf("%s:%d", domain, qtype)
		if value, ok := r.cache.Get(cacheKey); ok {
			if cached, ok := value.(CacheEntry); ok && time.Now().Before(cached.Expiration) {
				return cached.Answer.Copy(), nil
			}
		}

		// Параллельные запросы к серверам
		type result struct {
			resp *dns.Msg
			err  error
		}
		results := make(chan result, len(currentServers))
		var wg sync.WaitGroup

		for _, server := range currentServers {
			wg.Add(1)
			go func(server string) {
				defer wg.Done()
				conn := r.connPool.Get().(net.Conn)
				defer r.connPool.Put(conn)

				msg := new(dns.Msg)
				msg.SetQuestion(domain, qtype)
				msg.SetEdns0(4096, true)
				resp, _, err := r.client.ExchangeWithConn(msg, &dns.Conn{Conn: conn})
				results <- result{resp: resp, err: err}
			}(server)
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		var resp *dns.Msg
		for res := range results {
			if res.err == nil && res.resp != nil && res.resp.Rcode == dns.RcodeSuccess {
				resp = res.resp
				break
			}
		}

		if resp == nil {
			return nil, fmt.Errorf("no valid response from servers for %s", domain)
		}

		// Проверяем DNSSEC (базовая поддержка)
		if opt := resp.IsEdns0(); opt != nil && opt.Do() {
			log.Debug().Str("domain", domain).Msg("DNSSEC requested, validation not implemented")
		}

		// Кэшируем ответ
		if resp.Rcode == dns.RcodeSuccess {
			ttl := time.Duration(getMinTTL(resp)) * time.Second
			r.cache.SetWithTTL(cacheKey, CacheEntry{
				Answer:     resp.Copy(),
				Expiration: time.Now().Add(ttl),
			}, 1, ttl)
		}

		// Проверяем, есть ли ответ на запрос
		if len(resp.Answer) > 0 && resp.Question[0].Qtype == qtype {
			return resp, nil
		}

		// Обрабатываем CNAME
		for _, rr := range resp.Answer {
			if cname, ok := rr.(*dns.CNAME); ok && qtype != dns.TypeCNAME {
				r.cnameFollows.Inc()
				log.Info().Str("domain", domain).Str("cname", cname.Target).Msg("Following CNAME")
				if _, seen := seenDomains[cname.Target]; seen {
					return nil, fmt.Errorf("CNAME loop detected for %s", cname.Target)
				}
				seenDomains[cname.Target] = struct{}{}
				domain = cname.Target
				continue
			}
		}

		// Получаем NS записи и их IP-адреса (A и AAAA)
		var nextServers []string
		for _, ns := range resp.Ns {
			if nsRr, ok := ns.(*dns.NS); ok {
				// Запрашиваем A и AAAA для NS
				for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
					nsMsg := new(dns.Msg)
					nsMsg.SetQuestion(nsRr.Ns, qtype)
					nsMsg.SetEdns0(4096, true)
					nsResp, err := r.resolve(nsMsg)
					if err != nil {
						log.Warn().Err(err).Str("ns", nsRr.Ns).Str("type", dns.TypeToString[qtype]).Msg("Failed to resolve NS")
						continue
					}
					for _, rr := range nsResp.Answer {
						switch v := rr.(type) {
						case *dns.A:
							nextServers = append(nextServers, fmt.Sprintf("%s:53", v.A.String()))
						case *dns.AAAA:
							nextServers = append(nextServers, fmt.Sprintf("[%s]:53", v.AAAA.String()))
						}
					}
				}
			}
		}

		if len(nextServers) == 0 {
			return resp, nil
		}

		currentServers = nextServers
	}

	return nil, fmt.Errorf("max iterations exceeded for %s", domain)
}

// getMinTTL возвращает минимальный TTL из ответа
func getMinTTL(msg *dns.Msg) uint32 {
	var minTTL uint32 = 3600
	for _, rr := range append(msg.Answer, msg.Ns...) {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	if minTTL == 0 {
		minTTL = 300
	}
	return minTTL
}

func main() {
	// Инициализация логгера
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

	// Конфигурация
	port := os.Getenv("DNS_PORT")
	if port == "" {
		port = "8053"
	}

	resolver, err := NewResolver()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize resolver")
	}

	// Запуск очистки кэша
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go resolver.cleanCache(ctx)

	// Запуск Prometheus-метрик
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Info().Msg("Starting Prometheus metrics server on :9090")
		if err := http.ListenAndServe(":9090", nil); err != nil {
			log.Fatal().Err(err).Msg("Failed to start metrics server")
		}
	}()

	// Запуск DNS-сервера
	server := &dns.Server{Addr: ":" + port, Net: "udp", UDPSize: 4096}
	dns.HandleFunc(".", resolver.HandleDNS)

	log.Info().Str("port", port).Msg("Starting ASTRACAT RESOLVER")
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatal().Err(err).Msg("Failed to start DNS server")
		}
	}()

	// Обработка graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	log.Info().Msg("Shutting down ASTRACAT RESOLVER")
	cancel()
	server.Shutdown()
}
