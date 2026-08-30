package cache

import (
	"container/list"
	"hash/fnv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"balancedns/internal/metrics"

	"github.com/miekg/dns"
)

const maxShards = 64

type key struct {
	fqdn  string
	qtype uint16
}

type entry struct {
	key       key
	message   *dns.Msg
	expiresAt time.Time
	element   *list.Element
}

type shard struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[key]*entry
}

type Cache struct {
	minTTL  time.Duration
	maxTTL  time.Duration
	shards  []shard
	metrics *metrics.Provider

	// entries is a running count of cached items, updated atomically on
	// insert/evict/expire. It is O(1) and avoids locking all shards from
	// within a shard-critical section (which would deadlock).
	entries atomic.Int64
}

func New(capacity int, minTTLSeconds, maxTTLSeconds uint32) *Cache {
	return NewWithMetrics(capacity, minTTLSeconds, maxTTLSeconds, nil)
}

func NewWithMetrics(capacity int, minTTLSeconds, maxTTLSeconds uint32, m *metrics.Provider) *Cache {
	if capacity <= 0 {
		capacity = 1
	}

	shardCount := chooseShardCount(capacity)
	shards := make([]shard, shardCount)
	for i := range shards {
		shards[i] = shard{
			cap:   shardCapacity(capacity, shardCount, i),
			ll:    list.New(),
			items: make(map[key]*entry),
		}
	}

	return &Cache{
		minTTL:  time.Duration(minTTLSeconds) * time.Second,
		maxTTL:  time.Duration(maxTTLSeconds) * time.Second,
		shards:  shards,
		metrics: m,
	}
}

func (c *Cache) Get(q dns.Question) (*dns.Msg, bool) {
	k := makeKey(q)
	s := &c.shards[c.shardIndex(k)]

	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[k]
	if !ok {
		c.incMiss()
		return nil, false
	}
	if time.Now().After(item.expiresAt) {
		s.remove(item)
		c.entries.Add(-1)
		c.incEviction()
		c.incMiss()
		return nil, false
	}

	s.ll.MoveToFront(item.element)
	c.incHit()
	return item.message.Copy(), true
}

// Set stores response in the cache. The caller must not mutate response after
// Set returns: the cache retains a reference to it (no defensive copy) to avoid
// a double deep-copy on the hot path. Get always returns a deep copy, so the
// stored message is never exposed directly to readers.
func (c *Cache) Set(q dns.Question, response *dns.Msg) {
	if response == nil {
		return
	}

	ttl := c.extractTTL(response)
	if ttl <= 0 {
		return
	}

	k := makeKey(q)
	s := &c.shards[c.shardIndex(k)]
	expiresAt := time.Now().Add(ttl)

	s.mu.Lock()
	defer s.mu.Unlock()

	if current, ok := s.items[k]; ok {
		current.message = response
		current.expiresAt = expiresAt
		s.ll.MoveToFront(current.element)
		return
	}

	elem := s.ll.PushFront(k)
	s.items[k] = &entry{
		key:       k,
		message:   response,
		expiresAt: expiresAt,
		element:   elem,
	}

	if len(s.items) > s.cap {
		s.evictOldest()
		c.entries.Add(-1)
		c.incEviction()
	}
	c.entries.Add(1)
	c.reportEntries()
}

func (c *Cache) incHit() {
	if c.metrics != nil {
		c.metrics.IncCacheHits()
	}
}

func (c *Cache) incMiss() {
	if c.metrics != nil {
		c.metrics.IncCacheMisses()
	}
}

func (c *Cache) incEviction() {
	if c.metrics != nil {
		c.metrics.IncCacheEvictions()
	}
}

// reportEntries publishes the running entry count. It is O(1) and safe to
// call from within a shard-critical section.
func (c *Cache) reportEntries() {
	if c.metrics != nil {
		c.metrics.SetCacheEntries(int(c.entries.Load()))
	}
}

func (c *Cache) extractTTL(msg *dns.Msg) time.Duration {
	minRR := uint32(0)
	update := func(rr dns.RR) {
		h := rr.Header()
		if h == nil || h.Ttl == 0 {
			return
		}
		if minRR == 0 || h.Ttl < minRR {
			minRR = h.Ttl
		}
	}

	for _, rr := range msg.Answer {
		update(rr)
	}
	for _, rr := range msg.Ns {
		update(rr)
	}
	for _, rr := range msg.Extra {
		update(rr)
	}

	ttl := c.minTTL
	if minRR > 0 {
		ttl = time.Duration(minRR) * time.Second
	}
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	return ttl
}

func (s *shard) evictOldest() {
	tail := s.ll.Back()
	if tail == nil {
		return
	}
	k, ok := tail.Value.(key)
	if !ok {
		s.ll.Remove(tail)
		return
	}
	if item, found := s.items[k]; found {
		s.remove(item)
		return
	}
	s.ll.Remove(tail)
}

func (s *shard) remove(e *entry) {
	delete(s.items, e.key)
	s.ll.Remove(e.element)
}

func (c *Cache) shardIndex(k key) int {
	h := fnv.New64a()
	_, _ = h.Write([]byte(k.fqdn))
	_, _ = h.Write([]byte{byte(k.qtype >> 8), byte(k.qtype)})
	return int(h.Sum64() % uint64(len(c.shards)))
}

func chooseShardCount(capacity int) int {
	if capacity < 1024 {
		return 1
	}
	if capacity < maxShards {
		return capacity
	}
	return maxShards
}

func shardCapacity(total, shards, idx int) int {
	base := total / shards
	rest := total % shards
	if idx < rest {
		base++
	}
	if base <= 0 {
		return 1
	}
	return base
}

func makeKey(q dns.Question) key {
	return key{
		fqdn:  strings.ToLower(dns.Fqdn(q.Name)),
		qtype: q.Qtype,
	}
}
