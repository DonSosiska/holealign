// Package collector is the root-side half of the privilege separation (docs/contracts.md §2): it
// serves host data over a unix socket to the unprivileged sender.
//
// The process that runs this code parses untrusted local files as root and must have no
// network. Therefore this package (and everything it imports) must not import the HTTP
// transport; TestNoTransportDependency enforces that with `go list -deps`.
package collector

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/DonSosiska/holealign/internal/agent/hostdata"
	"github.com/DonSosiska/holealign/internal/model"
)

// DefaultInventoryMinGap: at most one inventory scan per this interval, whoever asks.
const DefaultInventoryMinGap = 10 * time.Minute

const (
	requestReadTimeout   = 10 * time.Second
	responseWriteTimeout = 5 * time.Minute
	maxConns             = 8
	acceptBackoff        = 100 * time.Millisecond
)

// FactsDeadline bounds one facts request end to end (a hung collector must not pin a
// slot of the facts semaphore forever); it is also cancelled when the client goes away.
const FactsDeadline = 2 * time.Minute

// temporaryAcceptError reports errors after which accepting may succeed again.
func temporaryAcceptError(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM)
}

// Server answers requests from the sender.
type Server struct {
	Backend    hostdata.Source // applies all collection policies (facts, inventory)
	SocketPath string
	// AllowedUIDs may connect in addition to root (uid 0 is always allowed).
	AllowedUIDs []uint32
	// Group, when it resolves, becomes the group owner of the socket (mode 0660).
	Group string
	// InventoryMinGap: 0 = DefaultInventoryMinGap, negative disables (tests only).
	InventoryMinGap time.Duration
	// PeerUID reads the connecting uid (SO_PEERCRED on Linux); nil = the platform default.
	PeerUID func(net.Conn) (uint32, error)
	Log     *slog.Logger

	// ChangeMinGap: when a package change is pending, the cached inventory is bypassed, but at
	// most one real scan per this interval (0 = DefaultChangeMinGap, negative = no limit).
	ChangeMinGap time.Duration
	// FactsCacheTTL: identical facts requests within this window get the previous result
	// (0 = DefaultFactsCacheTTL, negative disables the cache).
	FactsCacheTTL time.Duration
	// FactsTimeout bounds one facts request (0 = FactsDeadline).
	FactsTimeout time.Duration

	initOnce sync.Once
	factsSem chan struct{} // concurrent facts collections
	invSem   chan struct{} // concurrent inventory scans

	factsMu    sync.Mutex
	factsCache map[string]factsEntry

	invMu         sync.Mutex
	invAt         time.Time
	invCache      *model.InventoryPayload
	invErr        error
	invRunning    bool // a scan is in progress: invCache/invErr are not valid yet
	changePending bool // a package change was reported and no real scan has run since
}

// Bounds against a compromised sender (it may ask as often as it likes).
const (
	DefaultChangeMinGap  = 2 * time.Minute
	DefaultFactsCacheTTL = 30 * time.Second
	maxFactsOps          = 2
	maxInventoryOps      = 1
	maxFactsCacheEntries = 4
)

// errBusy is returned (instead of queueing) when too many collections already run.
var errBusy = errors.New("busy: too many concurrent operations, try again later")

type factsEntry struct {
	at    time.Time
	facts model.Facts
}

func (s *Server) init() {
	s.initOnce.Do(func() {
		s.factsSem = make(chan struct{}, maxFactsOps)
		s.invSem = make(chan struct{}, maxInventoryOps)
		s.factsCache = map[string]factsEntry{}
	})
}

// facts serves the facts of a request set: identical sets within FactsCacheTTL share one
// collection, and at most maxFactsOps collections run at once (others fail fast).
func (s *Server) facts(ctx context.Context, reqs []model.FactRequest) (model.Facts, error) {
	s.init()
	ttl := s.FactsCacheTTL
	if ttl == 0 {
		ttl = DefaultFactsCacheTTL
	}
	key := ""
	if ttl > 0 {
		kb, err := json.Marshal(reqs)
		if err != nil {
			return nil, err
		}
		key = string(kb)
		s.factsMu.Lock()
		if e, ok := s.factsCache[key]; ok && time.Since(e.at) < ttl {
			s.factsMu.Unlock()
			return e.facts, nil
		}
		s.factsMu.Unlock()
	}
	select {
	case s.factsSem <- struct{}{}:
		defer func() { <-s.factsSem }()
	default:
		return nil, errBusy
	}
	f, err := s.Backend.Facts(ctx, reqs)
	if err != nil || ttl <= 0 || ctx.Err() != nil { // partial results of a cancelled run are not cached
		return f, err
	}
	s.factsMu.Lock()
	defer s.factsMu.Unlock()
	now := time.Now()
	for k, e := range s.factsCache {
		if now.Sub(e.at) >= ttl {
			delete(s.factsCache, k)
		}
	}
	if len(s.factsCache) >= maxFactsCacheEntries {
		clear(s.factsCache)
	}
	s.factsCache[key] = factsEntry{at: now, facts: f}
	return f, nil
}

// PeerAllowed is the authorisation decision: root, or one of the allowed uids.
func PeerAllowed(uid uint32, allowed []uint32) bool {
	if uid == 0 {
		return true
	}
	for _, a := range allowed {
		if uid == a {
			return true
		}
	}
	return false
}

// ResolveUser returns the uid and the primary group name's gid of a user.
func ResolveUser(name string) (uid uint32, gid int, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	g, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uint32(id), g, nil
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Listen creates the socket (dir 0750, socket 0660, optional group) and returns the listener.
func (s *Server) Listen() (net.Listener, error) {
	gid := -1
	if s.Group != "" {
		if u, err := user.LookupGroup(s.Group); err == nil {
			if n, err := strconv.Atoi(u.Gid); err == nil {
				gid = n
			}
		} else {
			s.log().Warn("collector group not found; socket stays root-only", "group", s.Group, "err", err)
		}
	}
	dir := filepath.Dir(s.SocketPath)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
		if gid >= 0 {
			_ = os.Chown(dir, -1, gid)
		}
	}
	if fi, err := os.Lstat(s.SocketPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", s.SocketPath)
		}
		_ = os.Remove(s.SocketPath) // stale socket of a previous run
	}
	old := setUmask(0o117) // socket created 0660
	l, err := net.Listen("unix", s.SocketPath)
	setUmask(old)
	if err != nil {
		return nil, err
	}
	if err := s.fixSocket(gid); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// fixSocket makes the socket 0660 and, when a group is configured, group-owned by it. Under
// systemd (Group=holealign, UMask=0007) the socket is created that way already, and the
// unit's seccomp filter denies chown (@chown is part of @privileged): both calls are skipped
// when the result is already right, and EPERM is not fatal when the end state is correct.
func (s *Server) fixSocket(gid int) error {
	state := func() (mode os.FileMode, g int, gok bool, err error) {
		fi, err := os.Lstat(s.SocketPath)
		if err != nil {
			return 0, 0, false, err
		}
		g, gok = fileGID(fi)
		return fi.Mode().Perm(), g, gok, nil
	}
	mode, g, gok, err := state()
	if err != nil {
		return err
	}
	if mode != 0o660 {
		if err := os.Chmod(s.SocketPath, 0o660); err != nil {
			if m2, _, _, serr := state(); !(errors.Is(err, os.ErrPermission) && serr == nil && m2 == 0o660) {
				return err
			}
		}
	}
	if gid >= 0 && !(gok && g == gid) {
		if err := os.Chown(s.SocketPath, -1, gid); err != nil {
			if _, g2, ok2, serr := state(); !(errors.Is(err, os.ErrPermission) && serr == nil && ok2 && g2 == gid) {
				s.log().Warn("cannot set socket group", "err", err)
			}
		}
	}
	return nil
}

// Serve listens and serves until ctx ends.
func (s *Server) Serve(ctx context.Context) error {
	l, err := s.Listen()
	if err != nil {
		return err
	}
	return s.ServeListener(ctx, l)
}

// ServeListener serves on l until ctx ends, then closes it and waits for running requests.
func (s *Server) ServeListener(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConns)
	defer func() {
		wg.Wait()
		_ = os.Remove(s.SocketPath)
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if temporaryAcceptError(err) {
				// fd exhaustion or an aborted connection must not end the collector.
				s.log().Warn("collector: temporary accept error", "err", err)
				select {
				case <-time.After(acceptBackoff):
				case <-ctx.Done():
					return nil
				}
				continue
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close() // too many concurrent requests
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer conn.Close()
			defer func() {
				if r := recover(); r != nil {
					s.log().Error("collector request panicked", "panic", fmt.Sprint(r))
				}
			}()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	peer := s.PeerUID
	if peer == nil {
		peer = peerUID
	}
	uid, err := peer(conn)
	if err != nil {
		s.log().Warn("rejecting connection: cannot determine peer credentials", "err", err)
		return
	}
	if !PeerAllowed(uid, s.AllowedUIDs) {
		s.log().Warn("rejecting connection from unauthorised uid", "uid", uid)
		return
	}
	conn.SetReadDeadline(time.Now().Add(requestReadTimeout))
	req, err := ReadRequest(conn)
	if err != nil {
		s.respond(conn, false, hostdata.Response{OK: false, Error: err.Error()})
		return
	}
	conn.SetReadDeadline(time.Time{})

	resp := hostdata.Response{OK: true}
	switch req.Op {
	case hostdata.OpFacts:
		fctx, cancel := s.factsContext(ctx, conn)
		f, err := s.facts(fctx, req.FactRequests)
		cancel()
		resp.Facts = f
		resp = fail(resp, err)
	case hostdata.OpInventory:
		inv, err := s.inventory(ctx)
		resp.Inventory = inv
		resp = fail(resp, err)
	case hostdata.OpOSInfo:
		info, err := s.Backend.Info(ctx)
		resp.OS, resp.MachineID = &info.OS, info.MachineID
		resp = fail(resp, err)
	case hostdata.OpChanged:
		c, err := s.Backend.Changed(ctx)
		// The backend consumes its change signal when it reports it. Keep it here until a real
		// scan has run, otherwise a cached inventory would swallow the change.
		s.invMu.Lock()
		if err == nil && c {
			s.changePending = true
		}
		resp.Changed = s.changePending
		s.invMu.Unlock()
		resp = fail(resp, err)
	case hostdata.OpForgetEnrollToken:
		resp = fail(resp, s.forgetEnrollToken(ctx))
	default:
		resp = hostdata.Response{Error: "unknown op"}
	}
	s.respond(conn, req.Gzip && req.Op == hostdata.OpInventory, resp)
}

// factsContext derives the context of one facts request: it ends after FactsTimeout (default
// FactsDeadline) and as soon as the client closes its end of conn (the request is fully read
// and the client sends nothing more, so any read result means it went away). The returned
// cancel must be called when the request is done; it also stops the watcher.
func (s *Server) factsContext(ctx context.Context, conn net.Conn) (context.Context, context.CancelFunc) {
	d := s.FactsTimeout
	if d <= 0 {
		d = FactsDeadline
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var b [1]byte
		_, _ = conn.Read(b[:]) // returns on EOF, error, or the deadline set below
		cancel()
	}()
	return ctx, func() {
		cancel()
		_ = conn.SetReadDeadline(time.Now()) // unblock the watcher
		<-done
		_ = conn.SetReadDeadline(time.Time{})
	}
}

func fail(r hostdata.Response, err error) hostdata.Response {
	if err != nil {
		return hostdata.Response{OK: false, Error: err.Error()}
	}
	return r
}

// forgetEnrollToken asks the backend to blank the enrollment token in the config file.
func (s *Server) forgetEnrollToken(ctx context.Context) error {
	f, ok := s.Backend.(hostdata.EnrollTokenForgetter)
	if !ok {
		return errors.New("forgetting the enrollment token is not supported by this backend")
	}
	return f.ForgetEnrollToken(ctx)
}

// inventory runs at most one real scan per InventoryMinGap; requests inside the window get
// the previous result (payload or error), except that a pending package change bypasses the
// cache (still at most one real scan per ChangeMinGap). At most one scan runs at a time;
// other requests that need a scan fail fast with a "busy" error instead of queueing.
func (s *Server) inventory(ctx context.Context) (*model.InventoryPayload, error) {
	s.init()
	gap := s.InventoryMinGap
	if gap == 0 {
		gap = DefaultInventoryMinGap
	}
	changeGap := s.ChangeMinGap
	if changeGap == 0 {
		changeGap = DefaultChangeMinGap
	}
	// cached reports whether the previous result may be served; call with invMu held.
	cached := func() bool {
		if gap <= 0 || s.invAt.IsZero() || s.invRunning {
			return false
		}
		since := time.Since(s.invAt)
		if since >= gap {
			return false
		}
		return !(s.changePending && since >= changeGap)
	}
	serve := func() (*model.InventoryPayload, error) {
		if s.invErr != nil {
			return nil, s.invErr
		}
		return s.invCache, nil
	}

	s.invMu.Lock()
	if cached() {
		defer s.invMu.Unlock()
		return serve()
	}
	s.invMu.Unlock()

	select {
	case s.invSem <- struct{}{}:
		defer func() { <-s.invSem }()
	default:
		return nil, errBusy
	}

	s.invMu.Lock()
	if cached() { // a scan finished while we waited for the slot
		defer s.invMu.Unlock()
		return serve()
	}
	s.invAt = time.Now()
	s.invRunning = true
	pending := s.changePending
	s.changePending = false // a real scan sees the change
	s.invMu.Unlock()

	p, err := s.Backend.Inventory(ctx)

	s.invMu.Lock()
	defer s.invMu.Unlock()
	s.invRunning = false
	if err != nil {
		s.invCache, s.invErr = nil, err
		s.changePending = s.changePending || pending // not scanned after all
		return nil, err
	}
	s.invCache, s.invErr = &p, nil
	if gap > 0 {
		// do not hold a large payload longer than needed
		at := s.invAt
		time.AfterFunc(gap, func() {
			s.invMu.Lock()
			if s.invAt.Equal(at) {
				s.invCache = nil
			}
			s.invMu.Unlock()
		})
	}
	return &p, nil
}

// ReadRequest reads one newline-terminated JSON request of at most MaxRequestBytes.
func ReadRequest(r io.Reader) (hostdata.Request, error) {
	var req hostdata.Request
	br := bufio.NewReaderSize(io.LimitReader(r, hostdata.MaxRequestBytes+1), 4096)
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > hostdata.MaxRequestBytes {
			return req, errors.New("request too large")
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return req, errors.New("incomplete request (no terminating newline)")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("bad request: %v", err)
	}
	return req, nil
}

func (s *Server) respond(conn net.Conn, gz bool, resp hostdata.Response) {
	conn.SetWriteDeadline(time.Now().Add(responseWriteTimeout))
	var w io.Writer = conn
	var zw *gzip.Writer
	if gz && resp.OK {
		zw = gzip.NewWriter(conn)
		w = zw
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log().Warn("collector: writing response failed", "err", err)
	}
	if zw != nil {
		zw.Close()
	}
}
