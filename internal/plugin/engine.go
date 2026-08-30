package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"balancedns/internal/config"
	"balancedns/internal/metrics"

	"github.com/miekg/dns"
	lua "github.com/yuin/gopher-lua"
)

type Action string

const (
	ActionForward   Action = "FORWARD"
	ActionBlock     Action = "BLOCK"
	ActionRewrite   Action = "REWRITE"
	ActionLocalData Action = "LOCAL_DATA"
)

type LocalData struct {
	IPs []net.IP
	TTL uint32
}

type Decision struct {
	Action   Action
	Question dns.Question
	Local    LocalData
}

type Engine struct {
	runners []runner
	metrics *metrics.Provider
}

type runner interface {
	Name() string
	Run(q dns.Question) (Decision, error)
}

func NewEngine(entries []config.PluginEntry, defaultTimeout time.Duration) (*Engine, error) {
	return NewEngineWithMetrics(entries, defaultTimeout, nil)
}

func NewEngineWithMetrics(entries []config.PluginEntry, defaultTimeout time.Duration, m *metrics.Provider) (*Engine, error) {
	runners := make([]runner, 0, len(entries))

	for i := range entries {
		entry := entries[i]
		timeout := defaultTimeout
		if entry.TimeoutMS > 0 {
			timeout = time.Duration(entry.TimeoutMS) * time.Millisecond
		}

		switch entry.Runtime {
		case "lua":
			r, err := newLuaRunner(entry, timeout)
			if err != nil {
				return nil, err
			}
			runners = append(runners, r)
		case "go_exec":
			r, err := newGoExecRunner(entry, timeout)
			if err != nil {
				return nil, err
			}
			runners = append(runners, r)
		default:
			return nil, fmt.Errorf("unsupported plugin runtime %q", entry.Runtime)
		}
	}

	return &Engine{runners: runners, metrics: m}, nil
}

func (e *Engine) Decide(initial dns.Question) (Decision, error) {
	current := normalizeQuestion(initial)
	decision := Decision{Action: ActionForward, Question: current}

	for _, r := range e.runners {
		start := time.Now()
		if e.metrics != nil {
			e.metrics.IncPluginRequest(r.Name())
		}
		d, err := r.Run(current)
		if e.metrics != nil {
			e.metrics.ObservePluginDuration(r.Name(), time.Since(start))
		}
		if err != nil {
			if e.metrics != nil {
				e.metrics.IncPluginError(r.Name())
			}
			return Decision{}, fmt.Errorf("plugin %s: %w", r.Name(), err)
		}

		switch d.Action {
		case ActionForward:
			current = normalizeQuestion(d.Question)
			decision.Question = current
		case ActionRewrite:
			current = normalizeQuestion(d.Question)
			decision.Action = ActionRewrite
			decision.Question = current
		case ActionBlock:
			d.Question = current
			return d, nil
		case ActionLocalData:
			d.Question = current
			return d, nil
		default:
			return Decision{}, fmt.Errorf("unsupported action %q", d.Action)
		}
	}

	return decision, nil
}

type luaRunner struct {
	name    string
	src     string
	timeout time.Duration
	pool    sync.Pool
}

func newLuaRunner(entry config.PluginEntry, timeout time.Duration) (*luaRunner, error) {
	data, err := os.ReadFile(entry.Path)
	if err != nil {
		return nil, fmt.Errorf("read lua script %q: %w", entry.Path, err)
	}

	r := &luaRunner{
		name:    nonEmpty(entry.Name, filepath.Base(entry.Path)),
		src:     string(data),
		timeout: timeout,
	}
	r.pool.New = func() any { return newSandboxState() }
	return r, nil
}

func (r *luaRunner) Name() string { return r.name }

func (r *luaRunner) Run(q dns.Question) (Decision, error) {
	L := r.pool.Get().(*lua.LState)
	defer r.recycle(L)

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	L.SetContext(ctx)

	if err := L.DoString(r.src); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Decision{}, fmt.Errorf("execution timeout (%s)", r.timeout)
		}
		return Decision{}, err
	}

	fn := L.GetGlobal("handle")
	if fn.Type() != lua.LTFunction {
		return Decision{}, errors.New("function handle(question) is required")
	}

	questionTable := L.NewTable()
	questionTable.RawSetString("domain", lua.LString(q.Name))
	questionTable.RawSetString("type", lua.LString(dns.TypeToString[q.Qtype]))
	questionTable.RawSetString("qtype", lua.LNumber(q.Qtype))

	if err := L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, questionTable); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Decision{}, fmt.Errorf("execution timeout (%s)", r.timeout)
		}
		return Decision{}, err
	}

	ret := L.Get(-1)
	L.Pop(1)
	return parseLuaDecision(ret, q)
}

func (r *luaRunner) recycle(L *lua.LState) {
	L.Close()
	r.pool.Put(newSandboxState())
}

func newSandboxState() *lua.LState {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	lua.OpenBase(L)
	lua.OpenTable(L)
	lua.OpenString(L)
	lua.OpenMath(L)
	return L
}

type goExecRunner struct {
	name    string
	path    string
	args    []string
	timeout time.Duration
}

type goExecInput struct {
	Question struct {
		Domain string `json:"domain"`
		Type   string `json:"type"`
		QType  uint16 `json:"qtype"`
	} `json:"question"`
}

type goExecOutput struct {
	Action        string          `json:"action"`
	RewriteDomain string          `json:"rewrite_domain"`
	RewriteType   json.RawMessage `json:"rewrite_type"`
	LocalData     *goExecLocal    `json:"local_data"`
}

type goExecLocal struct {
	IP  string   `json:"ip"`
	IPs []string `json:"ips"`
	TTL uint32   `json:"ttl"`
}

func newGoExecRunner(entry config.PluginEntry, timeout time.Duration) (*goExecRunner, error) {
	path := entry.Path
	if !filepath.IsAbs(path) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve plugin path %q: %w", path, err)
		}
		path = abs
	}

	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat go plugin executable %q: %w", entry.Path, err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("go plugin path %q is directory, executable file required", entry.Path)
	}
	if st.Mode()&0111 == 0 {
		return nil, fmt.Errorf("go plugin executable %q is not executable", entry.Path)
	}

	return &goExecRunner{
		name:    nonEmpty(entry.Name, filepath.Base(entry.Path)),
		path:    path,
		args:    append([]string(nil), entry.Args...),
		timeout: timeout,
	}, nil
}

func (r *goExecRunner) Name() string { return r.name }

func (r *goExecRunner) Run(q dns.Question) (Decision, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	payload := goExecInput{}
	payload.Question.Domain = q.Name
	payload.Question.Type = dns.TypeToString[q.Qtype]
	payload.Question.QType = q.Qtype

	body, err := json.Marshal(payload)
	if err != nil {
		return Decision{}, fmt.Errorf("marshal input: %w", err)
	}

	cmd := exec.CommandContext(ctx, r.path, r.args...)
	cmd.Env = []string{}
	cmd.Dir = os.TempDir()
	cmd.Stdin = bytes.NewReader(body)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Decision{}, fmt.Errorf("execution timeout (%s)", r.timeout)
		}
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg != "" {
			return Decision{}, fmt.Errorf("exec failed: %v: %s", err, errMsg)
		}
		return Decision{}, fmt.Errorf("exec failed: %w", err)
	}

	if stdout.Len() == 0 {
		return Decision{}, errors.New("empty plugin output")
	}

	var out goExecOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return Decision{}, fmt.Errorf("decode output json: %w", err)
	}

	return parseGoDecision(out, q)
}

func parseLuaDecision(v lua.LValue, original dns.Question) (Decision, error) {
	out := Decision{Action: ActionForward, Question: normalizeQuestion(original)}

	if v == lua.LNil {
		return out, nil
	}

	if str, ok := v.(lua.LString); ok {
		action := normalizeAction(string(str))
		if action == ActionRewrite {
			return Decision{}, errors.New("REWRITE requires table return with rewrite_domain or rewrite_type")
		}
		out.Action = action
		return out, nil
	}

	tbl, ok := v.(*lua.LTable)
	if !ok {
		return Decision{}, errors.New("plugin return must be string, table, or nil")
	}

	actionStr := strings.TrimSpace(tbl.RawGetString("action").String())
	if actionStr == "" || actionStr == "nil" {
		actionStr = string(ActionForward)
	}

	rewriteDomain := strings.TrimSpace(tbl.RawGetString("rewrite_domain").String())
	if rewriteDomain == "nil" {
		rewriteDomain = ""
	}

	var rewriteType *uint16
	if rt := tbl.RawGetString("rewrite_type"); rt != lua.LNil {
		parsed, err := parseQTypeFromLua(rt)
		if err != nil {
			return Decision{}, fmt.Errorf("invalid rewrite_type: %w", err)
		}
		rewriteType = &parsed
	}

	var local *LocalData
	if normalizeAction(actionStr) == ActionLocalData {
		parsed, err := parseLocalDataLua(tbl.RawGetString("local_data"))
		if err != nil {
			return Decision{}, err
		}
		local = &parsed
	}

	return buildDecision(normalizeAction(actionStr), original, rewriteDomain, rewriteType, local)
}

func parseGoDecision(out goExecOutput, original dns.Question) (Decision, error) {
	action := normalizeAction(out.Action)

	var rewriteType *uint16
	if len(out.RewriteType) > 0 && string(out.RewriteType) != "null" {
		parsed, err := parseQTypeFromJSON(out.RewriteType)
		if err != nil {
			return Decision{}, fmt.Errorf("invalid rewrite_type: %w", err)
		}
		rewriteType = &parsed
	}

	var local *LocalData
	if action == ActionLocalData {
		if out.LocalData == nil {
			return Decision{}, errors.New("LOCAL_DATA action requires local_data object")
		}
		parsed, err := parseLocalDataGo(*out.LocalData)
		if err != nil {
			return Decision{}, err
		}
		local = &parsed
	}

	return buildDecision(action, original, out.RewriteDomain, rewriteType, local)
}

func buildDecision(action Action, original dns.Question, rewriteDomain string, rewriteType *uint16, local *LocalData) (Decision, error) {
	out := Decision{Action: action, Question: normalizeQuestion(original)}

	if rewriteDomain != "" {
		out.Question.Name = dns.Fqdn(rewriteDomain)
	}
	if rewriteType != nil {
		out.Question.Qtype = *rewriteType
	}

	if action == ActionRewrite && out.Question.Name == normalizeQuestion(original).Name && out.Question.Qtype == original.Qtype {
		return Decision{}, errors.New("REWRITE action requires rewrite_domain or rewrite_type")
	}
	if action == ActionLocalData {
		if local == nil {
			return Decision{}, errors.New("LOCAL_DATA action requires local_data")
		}
		out.Local = *local
	}
	return out, nil
}

func parseLocalDataLua(v lua.LValue) (LocalData, error) {
	if v == lua.LNil {
		return LocalData{}, errors.New("LOCAL_DATA action requires local_data table")
	}

	tbl, ok := v.(*lua.LTable)
	if !ok {
		return LocalData{}, errors.New("local_data must be table")
	}

	out := LocalData{TTL: 60}

	if ttl := tbl.RawGetString("ttl"); ttl != lua.LNil {
		ttlNum, err := parseUint32Lua(ttl)
		if err != nil {
			return LocalData{}, fmt.Errorf("invalid local_data.ttl: %w", err)
		}
		out.TTL = ttlNum
	}

	if ip := strings.TrimSpace(tbl.RawGetString("ip").String()); ip != "" && ip != "nil" {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return LocalData{}, fmt.Errorf("invalid local_data.ip: %q", ip)
		}
		out.IPs = append(out.IPs, parsed)
	}

	if ipsVal := tbl.RawGetString("ips"); ipsVal != lua.LNil {
		ipsTbl, ok := ipsVal.(*lua.LTable)
		if !ok {
			return LocalData{}, errors.New("local_data.ips must be array of strings")
		}
		ipsTbl.ForEach(func(_ lua.LValue, val lua.LValue) {
			ipStr := strings.TrimSpace(val.String())
			if ipStr == "" || ipStr == "nil" {
				return
			}
			if parsed := net.ParseIP(ipStr); parsed != nil {
				out.IPs = append(out.IPs, parsed)
			}
		})
	}

	if len(out.IPs) == 0 {
		return LocalData{}, errors.New("local_data requires ip or ips")
	}
	return out, nil
}

func parseLocalDataGo(in goExecLocal) (LocalData, error) {
	out := LocalData{TTL: 60}
	if in.TTL > 0 {
		out.TTL = in.TTL
	}

	if in.IP != "" {
		parsed := net.ParseIP(strings.TrimSpace(in.IP))
		if parsed == nil {
			return LocalData{}, fmt.Errorf("invalid local_data.ip: %q", in.IP)
		}
		out.IPs = append(out.IPs, parsed)
	}
	for _, ip := range in.IPs {
		parsed := net.ParseIP(strings.TrimSpace(ip))
		if parsed == nil {
			return LocalData{}, fmt.Errorf("invalid local_data.ips item: %q", ip)
		}
		out.IPs = append(out.IPs, parsed)
	}
	if len(out.IPs) == 0 {
		return LocalData{}, errors.New("local_data requires ip or ips")
	}
	return out, nil
}

func parseQTypeFromLua(v lua.LValue) (uint16, error) {
	switch typed := v.(type) {
	case lua.LNumber:
		n := int(typed)
		if n <= 0 || n > 65535 {
			return 0, errors.New("numeric type out of range")
		}
		return uint16(n), nil
	case lua.LString:
		s := strings.TrimSpace(strings.ToUpper(string(typed)))
		return parseQTypeString(s)
	default:
		return 0, fmt.Errorf("unsupported qtype type %s", v.Type().String())
	}
}

func parseQTypeFromJSON(raw json.RawMessage) (uint16, error) {
	var num uint16
	if err := json.Unmarshal(raw, &num); err == nil {
		if num == 0 {
			return 0, errors.New("qtype cannot be zero")
		}
		return num, nil
	}

	var str string
	if err := json.Unmarshal(raw, &str); err != nil {
		return 0, errors.New("rewrite_type must be string or number")
	}
	return parseQTypeString(strings.ToUpper(strings.TrimSpace(str)))
}

func parseQTypeString(s string) (uint16, error) {
	if s == "" {
		return 0, errors.New("empty qtype")
	}
	if n, ok := dns.StringToType[s]; ok {
		return n, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("unknown type %q", s)
	}
	if n <= 0 || n > 65535 {
		return 0, errors.New("numeric type out of range")
	}
	return uint16(n), nil
}

func parseUint32Lua(v lua.LValue) (uint32, error) {
	switch typed := v.(type) {
	case lua.LNumber:
		n := int64(typed)
		if n < 0 || n > int64(^uint32(0)) {
			return 0, errors.New("out of range")
		}
		return uint32(n), nil
	case lua.LString:
		s := strings.TrimSpace(string(typed))
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return 0, err
		}
		return uint32(n), nil
	default:
		return 0, fmt.Errorf("unsupported type %s", v.Type().String())
	}
}

func normalizeAction(a string) Action {
	upper := strings.ToUpper(strings.TrimSpace(a))
	switch Action(upper) {
	case ActionForward, ActionBlock, ActionRewrite, ActionLocalData:
		return Action(upper)
	default:
		return ActionForward
	}
}

func normalizeQuestion(q dns.Question) dns.Question {
	q.Name = strings.ToLower(dns.Fqdn(q.Name))
	if q.Qclass == 0 {
		q.Qclass = dns.ClassINET
	}
	return q
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
