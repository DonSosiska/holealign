package notify

import (
	"cmp"
	"strconv"
	"strings"

	"github.com/DonSosiska/panoptes/internal/model"
)

// groupKey identifies events that describe one vulnerability on one target of one host.
// A CVE that hits several binary packages built from the same source (openssh-client,
// openssh-server, ...) yields one group and therefore one message.
type groupKey struct {
	kind                       model.EventKind
	hostID, vulnID, targetName string
}

// group is a set of events sent as one message.
type group struct {
	evs []model.Event
	idx []int // indexes of evs in the Notify input (may be nil outside Notify)
}

// groupEvents merges events by groupKey, preserving first-appearance order.
func groupEvents(events []model.Event) []group {
	idx := map[groupKey]int{}
	var out []group
	for n, ev := range events {
		k := groupKey{kind: ev.Kind, hostID: ev.Host.ID, vulnID: ev.Finding.VulnID, targetName: ev.Finding.Target}
		if ev.Kind.IsHealth() {
			k.targetName = "\x00health#" + strconv.Itoa(n) // health events are never merged
		}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, group{})
		}
		out[i].evs = append(out[i].evs, ev)
		out[i].idx = append(out[i].idx, n)
	}
	return out
}

// first returns the representative event (used for routing, the link and the header).
func (g group) first() model.Event { return g.evs[0] }

// maxCVSS, anyKEV: the group's importance is the maximum over its events.
func (g group) maxCVSS() float64 {
	best := 0.0
	for _, ev := range g.evs {
		best = max(best, ev.Finding.CVSS)
	}
	return best
}

func (g group) anyKEV() bool {
	for _, ev := range g.evs {
		if ev.Finding.KEV {
			return true
		}
	}
	return false
}

// compareGroups orders groups most important first: exploitable, unknown_critical, resolved;
// within a kind KEV first, then higher CVSS.
func compareGroups(a, b group) int {
	if c := cmp.Compare(kindRank(a.first().Kind), kindRank(b.first().Kind)); c != 0 {
		return c
	}
	if ka, kb := a.anyKEV(), b.anyKEV(); ka != kb {
		if ka {
			return -1
		}
		return 1
	}
	return cmp.Compare(b.maxCVSS(), a.maxCVSS())
}

func kindRank(k model.EventKind) int {
	switch k {
	case model.EventExploitable:
		return 0
	case model.EventUnknownCritical:
		return 1
	case model.EventResolved:
		return 2
	default:
		return 3
	}
}

// severityRank orders severity labels; unknown labels rank lowest.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// maxSeverity returns the highest severity label in the group ("" when none is set).
func (g group) maxSeverity() string {
	best := ""
	for _, ev := range g.evs {
		if severityRank(ev.Finding.Severity) > severityRank(best) {
			best = ev.Finding.Severity
		}
	}
	return best
}

func (g group) maxEPSS() float64 {
	best := 0.0
	for _, ev := range g.evs {
		best = max(best, ev.Finding.EPSS)
	}
	return best
}
