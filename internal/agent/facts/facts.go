// Package facts collects host facts (see docs/contracts.md §3).
package facts

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"runtime"
	"sync"

	"github.com/DonSosiska/holealign/internal/model"
)

// Env bundles the external dependencies of the collectors so tests can replace them.
type Env struct {
	Runner       CommandRunner
	FS           fs.FS  // rooted at "/", paths without leading slash ("etc/os-release")
	DockerSocket string // unix socket of the Docker Engine API

	// SafeOpen opens a resolved physical path without following symlinks
	// (TOCTOU-safe, linux only); nil falls back to FS.Open.
	SafeOpen func(physical string) (fs.File, error)
	// TreeTrust verifies that config trees (path globs) are root-owned and not
	// group/world-writable before the agent runs a tool that parses them as
	// root; nil = trust everything (tests).
	TreeTrust func(roots []string) error
	// TreeTrustStrict is like TreeTrust, used for explicitly configured or
	// included paths (e.g. nginx include globs, custom --conf-path): when a
	// pattern has no matches or its static prefix does not exist yet, the
	// nearest existing ancestor up to "/" is still verified. Nil falls back to
	// TreeTrust.
	TreeTrustStrict func(roots []string) error

	// NetDir is the FS-relative directory with tcp/tcp6/udp/udp6 for the sockets collector
	// ("" = "proc/net"). /proc/net is per network namespace; see Options.HostNetNS.
	NetDir string

	skips skipLog
}

// collector is one built-in collector; it returns the facts it could determine.
type collector struct {
	name string
	fn   func(ctx context.Context, env *Env) model.Facts
}

var builtinCollectors = []collector{
	{"os", collectOS},
	{"kernel", collectKernel},
	{"services", collectServices},
	{"sockets", collectSockets},
	{"sshd", collectSSHD},
	{"nginx", collectNginx},
	{"apache", collectApache},
	{"php", collectPHP},
	{"openssl", collectOpenSSL},
	{"docker", collectDocker},
	{"runc", collectRunc},
	{"sudo", collectSudo},
}

func defaultEnv() *Env {
	return &Env{
		Runner:          execRunner{},
		FS:              rootFS,
		DockerSocket:    "/var/run/docker.sock",
		SafeOpen:        safeOpen,
		TreeTrust:       treeTrusted,
		TreeTrustStrict: treeTrustedStrict,
	}
}

// Collect runs all built-in collectors plus the parametrised requests and returns
// the merged fact map. It never returns an error: failing collectors simply omit
// their facts (absent = unknown). Safe to call concurrently.
//
// On platforms other than Linux no facts are collected.
func Collect(ctx context.Context, reqs []model.FactRequest) model.Facts {
	return CollectWith(ctx, reqs, Options{})
}

// Options tune Collect.
type Options struct {
	// HostNetNS reads the listening sockets from /proc/1/net (the network namespace of PID 1,
	// i.e. the host) instead of /proc/net (the namespace of this process). Required when the
	// process runs in a private network namespace (systemd PrivateNetwork=yes, the collector
	// unit); there the sockets facts are omitted (unknown) if /proc/1/net is unreadable,
	// instead of reporting an empty, wrong list.
	HostNetNS bool
}

// CollectWith is Collect with options.
func CollectWith(ctx context.Context, reqs []model.FactRequest, o Options) model.Facts {
	if runtime.GOOS != "linux" {
		return model.Facts{}
	}
	env := defaultEnv()
	if o.HostNetNS {
		env.NetDir = hostNetDir
	}
	return collect(ctx, env, reqs)
}

// hostNetDir is the network namespace of PID 1.
const hostNetDir = "proc/1/net"

func collect(ctx context.Context, env *Env, reqs []model.FactRequest) model.Facts {
	results := make([]model.Facts, len(builtinCollectors))
	var wg sync.WaitGroup
	for i, c := range builtinCollectors {
		wg.Add(1)
		go func(i int, c collector) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("facts: collector %s panicked: %v", c.name, r)
					results[i] = nil
				}
			}()
			results[i] = c.fn(ctx, env)
		}(i, c)
	}
	wg.Wait()

	out := model.Facts{}
	for _, r := range results {
		for k, v := range r {
			out[k] = v
		}
	}

	if sk := env.skipped(); len(sk) > 0 {
		out["agent.skipped"] = sk
	}

	for name, v := range runFileMatchRequests(ctx, env, reqs) {
		out[name] = v
	}
	return out
}

// runFileMatchRequests evaluates the parametrised requests, isolating panics per request.
func runFileMatchRequests(ctx context.Context, env *Env, reqs []model.FactRequest) map[string]any {
	out := map[string]any{}
	ctx, cancel := context.WithTimeout(ctx, fmDeadline)
	defer cancel()
	bud := newFMBudget()
	for _, req := range selectFileMatchRequests(reqs) {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("facts: file.match %q panicked: %v", req.Name, fmt.Sprint(r))
				}
			}()
			if lines, ok := evalFileMatchB(ctx, env, req, bud); ok {
				out[req.Name] = lines
			}
		}()
	}
	return out
}
