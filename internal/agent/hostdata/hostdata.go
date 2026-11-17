// Package hostdata is the boundary between the code that reads (untrusted) local state and the
// code that talks to the network. The runner consumes a Source; the in-process implementation
// (Local, used by -mode all) collects directly, the socket implementation (Client, used by
// -mode sender) asks the root collector process over a unix socket (docs/contracts.md §2).
//
// This package must not import the HTTP transport: the collector process links it.
package hostdata

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/DonSosiska/panoptes/internal/agent/config"
	"github.com/DonSosiska/panoptes/internal/agent/facts"
	"github.com/DonSosiska/panoptes/internal/agent/hostinfo"
	"github.com/DonSosiska/panoptes/internal/agent/inventory"
	"github.com/DonSosiska/panoptes/internal/model"
)

// HostInfo is the OS description plus the hashed machine id.
type HostInfo struct {
	OS        model.OSInfo `json:"os"`
	MachineID string       `json:"machine_id"`
}

// Source provides everything the runner needs from the host.
type Source interface {
	// Facts collects the built-in facts plus the (policy-checked) parametrised requests.
	Facts(ctx context.Context, reqs []model.FactRequest) (model.Facts, error)
	// Inventory scans packages and images. It re-baselines the change detector.
	Inventory(ctx context.Context) (model.InventoryPayload, error)
	// Info returns OS information and the hashed machine id.
	Info(ctx context.Context) (HostInfo, error)
	// Changed reports whether package databases or images changed since the last call.
	Changed(ctx context.Context) (bool, error)
}

// Local collects in the current process with the agent's own privileges.
type Local struct {
	cfg  config.Config
	opts facts.Options

	mu      sync.Mutex
	det     *inventory.ChangeDetector
	pending bool // a change was reported and no scan has started since
}

// NewLocal returns an in-process Source. With hostNetNS the sockets facts come from /proc/1/net
// (needed in a private network namespace, see facts.Options).
func NewLocal(cfg config.Config, hostNetNS bool) *Local {
	return &Local{cfg: cfg, opts: facts.Options{HostNetNS: hostNetNS}, det: inventory.NewChangeDetector(cfg)}
}

func (l *Local) Facts(ctx context.Context, reqs []model.FactRequest) (model.Facts, error) {
	return facts.CollectWith(ctx, reqs, l.opts), nil
}

func (l *Local) Inventory(ctx context.Context) (model.InventoryPayload, error) {
	// baseline before the scan: a package change during the scan is seen by the next Changed
	l.mu.Lock()
	l.det.Reset(ctx)
	was := l.pending
	l.pending = false
	l.mu.Unlock()
	p, err := inventory.Scan(ctx, l.cfg)
	if err != nil && was {
		// the change is not reflected in any inventory yet
		l.mu.Lock()
		l.pending = true
		l.mu.Unlock()
	}
	return p, err
}

func (l *Local) Info(context.Context) (HostInfo, error) {
	return HostInfo{OS: hostinfo.CollectOSInfo(), MachineID: hostinfo.MachineID()}, nil
}

func (l *Local) Changed(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// the signal stays set until a real scan has started (see Inventory)
	if l.det.Changed(ctx) {
		l.pending = true
	}
	return l.pending, nil
}

// ForgetEnrollToken blanks enroll_token in the config file. Only root may do it in process
// (mode all as root, or the root collector); an unprivileged process leaves the file alone.
func (l *Local) ForgetEnrollToken(context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("not running as root: enroll_token left in the config file")
	}
	if l.cfg.Path == "" {
		return errors.New("config path unknown")
	}
	return config.ForgetEnrollToken(l.cfg.Path)
}
