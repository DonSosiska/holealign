// Package hostdata is the boundary between the code that reads (untrusted) local state and the
// code that talks to the network. The runner consumes a Source; the in-process implementation
// (Local, used by -mode all) collects directly, the socket implementation (Client, used by
// -mode sender) asks the root collector process over a unix socket (docs/contracts.md §2).
//
// This package must not import the HTTP transport: the collector process links it.
package hostdata

import (
	"context"
	"sync"

	"panoptes/internal/agent/config"
	"panoptes/internal/agent/facts"
	"panoptes/internal/agent/hostinfo"
	"panoptes/internal/agent/inventory"
	"panoptes/internal/model"
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

	mu  sync.Mutex
	det *inventory.ChangeDetector
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
	l.mu.Unlock()
	return inventory.Scan(ctx, l.cfg)
}

func (l *Local) Info(context.Context) (HostInfo, error) {
	return HostInfo{OS: hostinfo.CollectOSInfo(), MachineID: hostinfo.MachineID()}, nil
}

func (l *Local) Changed(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.det.Changed(ctx), nil
}
