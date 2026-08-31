// Асинхронный логгер DNS-запросов (для аналитики по-доменно).
// Пишет JSON-строки в файл без блокировки DNS-обработки.
package app

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// QueryLogEntry — запись о DNS-запросе.
type QueryLogEntry struct {
	ConfigID string `json:"config_id"`
	Domain   string `json:"domain"`
	Blocked  bool   `json:"blocked"`
	Qtype    string `json:"qtype"`
	Ts       int64  `json:"ts"` // unix ms
}

// QueryLogger — асинхронный логгер запросов в файл (JSON lines).
type QueryLogger struct {
	mu     sync.Mutex
	f      *os.File
	w      *bufio.Writer
	closed bool
}

// NewQueryLogger открывает файл для логов запросов.
func NewQueryLogger(path string) (*QueryLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &QueryLogger{f: f, w: bufio.NewWriterSize(f, 64*1024)}, nil
}

// Log асинхронно пишет запись (не блокирует DNS-ответ).
func (q *QueryLogger) Log(entry QueryLogEntry) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = q.w.Write(data)
	_ = q.w.WriteByte('\n')
	// Периодически сбрасываем буфер (не на каждый запрос, чтобы не замедлять).
	// Flush вызывается отдельно по таймеру.
}

// Flush сбрасывает буфер в файл.
func (q *QueryLogger) Flush() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	_ = q.w.Flush()
}

// Close закрывает логгер.
func (q *QueryLogger) Close() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	_ = q.w.Flush()
	_ = q.f.Close()
}

// FlushLoop периодически сбрасывает буфер (каждые interval).
func (q *QueryLogger) FlushLoop(interval time.Duration, stop <-chan struct{}) {
	if q == nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			q.Flush()
		case <-stop:
			q.Flush()
			return
		}
	}
}
