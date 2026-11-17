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
	"time"

	"panoptes/internal/agent/hostdata"
	"panoptes/internal/model"
)

// DefaultInventoryMinGap: at most one inventory scan per this interval, whoever asks.
const DefaultInventoryMinGap = 10 * time.Minute

const (
	requestReadTimeout   = 10 * time.Second
	responseWriteTimeout = 5 * time.Minute
	maxConns             = 8
)

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

	invMu    sync.Mutex
	invAt    time.Time
	invCache *model.InventoryPayload
	invErr   error
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
	if err := os.Chmod(s.SocketPath, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(s.SocketPath, -1, gid); err != nil {
			s.log().Warn("cannot set socket group", "err", err)
		}
	}
	return l, nil
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
		f, err := s.Backend.Facts(ctx, req.FactRequests)
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
		resp.Changed = c
		resp = fail(resp, err)
	default:
		resp = hostdata.Response{Error: "unknown op"}
	}
	s.respond(conn, req.Gzip && req.Op == hostdata.OpInventory, resp)
}

func fail(r hostdata.Response, err error) hostdata.Response {
	if err != nil {
		return hostdata.Response{OK: false, Error: err.Error()}
	}
	return r
}

// inventory runs at most one scan per InventoryMinGap; requests inside the window get the
// previous result (payload or error). Concurrent requests wait for the running scan.
func (s *Server) inventory(ctx context.Context) (*model.InventoryPayload, error) {
	gap := s.InventoryMinGap
	if gap == 0 {
		gap = DefaultInventoryMinGap
	}
	s.invMu.Lock()
	defer s.invMu.Unlock()
	if gap > 0 && !s.invAt.IsZero() && time.Since(s.invAt) < gap {
		if s.invErr != nil {
			return nil, s.invErr
		}
		return s.invCache, nil
	}
	s.invAt = time.Now()
	p, err := s.Backend.Inventory(ctx)
	if err != nil {
		s.invCache, s.invErr = nil, err
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
