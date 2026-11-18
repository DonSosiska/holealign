package inventory

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/DonSosiska/holealign/internal/agent/config"
)

var watchedPaths = []string{
	"/var/lib/dpkg/status",
	"/var/lib/rpm",
	"/usr/lib/sysimage/rpm",
	"/lib/apk/db/installed",
}

// ChangeDetector reports whether package databases or Docker images changed between calls.
type ChangeDetector struct {
	cfg   config.Config
	paths []string
	last  string
	init  bool
}

// NewChangeDetector creates a detector. The first Changed call sets the baseline and returns false.
func NewChangeDetector(cfg config.Config) *ChangeDetector {
	return &ChangeDetector{cfg: cfg, paths: watchedPaths}
}

// Changed returns true when the signature differs from the previous call.
func (d *ChangeDetector) Changed(ctx context.Context) bool {
	sig := d.signature(ctx)
	if !d.init {
		d.init = true
		d.last = sig
		return false
	}
	changed := sig != d.last
	d.last = sig
	return changed
}

// Reset re-baselines the detector (call after an inventory upload).
func (d *ChangeDetector) Reset(ctx context.Context) {
	d.last = d.signature(ctx)
	d.init = true
}

func (d *ChangeDetector) signature(ctx context.Context) string {
	var b strings.Builder
	for _, p := range d.paths {
		b.WriteString(p)
		b.WriteByte('=')
		b.WriteString(strconv.FormatInt(pathMtime(p), 10))
		b.WriteByte(';')
	}
	if dc := newDockerClient(d.cfg.DockerSocket); dc != nil {
		if imgs, err := dc.images(ctx); err == nil {
			ids := make([]string, 0, len(imgs))
			for _, im := range imgs {
				ids = append(ids, im.ID)
			}
			sort.Strings(ids)
			b.WriteString("images=")
			b.WriteString(strings.Join(ids, ","))
		}
	}
	return b.String()
}

// pathMtime returns the newest mtime (unix nanos) of a file, or of a directory and its direct
// children (rpm databases live in files inside the directory). Missing paths yield 0.
func pathMtime(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	newest := st.ModTime().UnixNano()
	if st.IsDir() {
		entries, err := os.ReadDir(p)
		if err == nil {
			for _, e := range entries {
				if info, err := e.Info(); err == nil && info.ModTime().UnixNano() > newest {
					newest = info.ModTime().UnixNano()
				}
			}
		}
	}
	return newest
}
