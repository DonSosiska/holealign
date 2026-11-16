// Package model holds the types shared by the Panoptes agent and server.
// Everything that crosses the wire or crosses a package boundary lives here.
// Changing a type in this package is a contract change: update docs/contracts.md too.
package model

import (
	"encoding/json"
	"time"
)

// APIVersion is the version prefix of the agent <-> server HTTP API.
const APIVersion = "v1"

// ---------------------------------------------------------------------------
// Agent <-> server API
// ---------------------------------------------------------------------------

// EnrollRequest is sent once by a new agent: POST /api/v1/enroll.
type EnrollRequest struct {
	Token        string   `json:"token"`      // enrollment token created by an admin
	Hostname     string   `json:"hostname"`   //
	MachineID    string   `json:"machine_id"` // /etc/machine-id, stable host identity
	Labels       []string `json:"labels"`     // from agent.yaml; used for Matrix routing
	AgentVersion string   `json:"agent_version"`
}

// EnrollResponse returns the per-agent credentials. The agent stores them in its state dir.
type EnrollResponse struct {
	AgentID  string `json:"agent_id"`
	AgentKey string `json:"agent_key"` // sent as "Authorization: Bearer <key>" afterwards
}

// CheckinRequest is the periodic heartbeat: POST /api/v1/checkin (every ~5 min).
type CheckinRequest struct {
	Hostname      string   `json:"hostname"`
	Labels        []string `json:"labels"`
	AgentVersion  string   `json:"agent_version"`
	OS            OSInfo   `json:"os"`
	Facts         Facts    `json:"facts,omitempty"`
	FactsComplete bool     `json:"facts_complete"` // true: Facts is a full snapshot (replace); false: a diff (merge; JSON null value = delete)
	InventoryHash string   `json:"inventory_hash"` // hash of the last inventory the agent has uploaded
}

// CheckinResponse tells the agent what to do next.
type CheckinResponse struct {
	FactRequests       []FactRequest `json:"fact_requests"`        // parametrised facts the server wants in addition to built-ins
	WantInventory      bool          `json:"want_inventory"`       // server has no inventory with InventoryHash -> upload now
	WantFullFacts      bool          `json:"want_full_facts"`      // server lost state -> send full snapshot next time
	NextCheckinSeconds int           `json:"next_checkin_seconds"` // 0 = keep agent default
}

// OSInfo is a summary of /etc/os-release plus kernel, sent on every check-in.
type OSInfo struct {
	ID         string `json:"id"`          // debian, ubuntu, rhel, alpine, ...
	VersionID  string `json:"version_id"`  // 12, 22.04, 9.4, 3.20
	PrettyName string `json:"pretty_name"` //
	Kernel     string `json:"kernel"`      // uname -r
	Arch       string `json:"arch"`        // amd64, arm64
}

// InventoryPayload is uploaded when packages change: POST /api/v1/inventory
// (Content-Type: application/json, Content-Encoding: gzip).
type InventoryPayload struct {
	CollectedAt time.Time         `json:"collected_at"`
	Hash        string            `json:"hash"` // sha256 over the target SBOMs; echoed back in CheckinRequest.InventoryHash
	Targets     []InventoryTarget `json:"targets"`
}

// TargetKind says what an inventory target is.
type TargetKind string

const (
	TargetHost           TargetKind = "host"            // the host root filesystem (OS + language packages)
	TargetContainerImage TargetKind = "container_image" // a Docker image present on the host
)

// InventoryTarget is one scanned thing on a host.
type InventoryTarget struct {
	Kind       TargetKind      `json:"kind"`
	Name       string          `json:"name"`                 // "host" or image reference (nginx:1.25)
	ImageID    string          `json:"image_id,omitempty"`   // sha256:... for images
	Containers []string        `json:"containers,omitempty"` // names of running containers that use this image
	SBOM       json.RawMessage `json:"sbom"`                 // CycloneDX JSON as produced by Syft
}

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

// Facts maps a fact name (see docs/contracts.md "Fact catalog") to its value.
// Allowed value types after JSON decoding: string, float64, bool, []any, map[string]any.
// A fact that is absent means "unknown", not "false".
type Facts map[string]any

// FactRequest asks the agent to collect a parametrised fact.
// Only collectors listed in docs/contracts.md exist; the agent rejects anything else.
// The server can never make the agent run an arbitrary command.
type FactRequest struct {
	Name      string            `json:"name" yaml:"name"`           // resulting fact name, e.g. "file.match:apache_proxy"
	Collector string            `json:"collector" yaml:"collector"` // currently only "file.match"
	Params    map[string]string `json:"params" yaml:"params"`       // file.match: path (glob), pattern (RE2)
}

// ---------------------------------------------------------------------------
// Findings and verdicts
// ---------------------------------------------------------------------------

// Verdict is the result of checking a vulnerable package against conditions.
type Verdict string

const (
	VerdictExploitable       Verdict = "exploitable"              // package vulnerable AND conditions met
	VerdictNotExploitable    Verdict = "affected_not_exploitable" // package vulnerable, conditions not met / mitigated
	VerdictConditionsUnknown Verdict = "conditions_unknown"       // no rule, or required facts missing
	VerdictNotAffected       Verdict = "not_affected"             // rule/VEX says the package is not affected at all
	VerdictResolved          Verdict = "resolved"                 // finding disappeared (package upgraded/removed)
)

// Finding is one (host, target, package, vulnerability) tuple.
type Finding struct {
	ID            int64      `json:"id"`
	HostID        string     `json:"host_id"`
	Target        string     `json:"target"`      // "host" or image reference
	TargetKind    TargetKind `json:"target_kind"` //
	PackageName   string     `json:"package_name"`
	PackageVer    string     `json:"package_version"`
	PackageType   string     `json:"package_type"` // deb, rpm, apk, python, npm, go-module, java-archive, ...
	PURL          string     `json:"purl"`
	VulnID        string     `json:"vuln_id"` // CVE-..., GHSA-..., as reported by the matcher
	Aliases       []string   `json:"aliases"` // related IDs (CVE <-> GHSA)
	Severity      string     `json:"severity"`
	CVSS          float64    `json:"cvss"`
	EPSS          float64    `json:"epss"`
	KEV           bool       `json:"kev"`
	FixedVersions []string   `json:"fixed_versions"`
	FixState      string     `json:"fix_state"` // fixed, not-fixed, wont-fix, unknown
	Verdict       Verdict    `json:"verdict"`
	VerdictReason string     `json:"verdict_reason"` // human readable: which facts made it exploitable
	RuleID        string     `json:"rule_id,omitempty"`
	RuleStatus    RuleStatus `json:"rule_status,omitempty"`
	FirstSeen     time.Time  `json:"first_seen"`
	LastSeen      time.Time  `json:"last_seen"`
}

// Host is the server-side view of an enrolled machine.
type Host struct {
	ID            string    `json:"id"`
	Hostname      string    `json:"hostname"`
	MachineID     string    `json:"machine_id"`
	Labels        []string  `json:"labels"`
	OS            OSInfo    `json:"os"`
	AgentVersion  string    `json:"agent_version"`
	LastCheckin   time.Time `json:"last_checkin"`
	InventoryHash string    `json:"inventory_hash"`
	Facts         Facts     `json:"facts"`
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

// RuleStatus tracks review state. Draft rules are applied but flagged in reports.
type RuleStatus string

const (
	RuleReviewed RuleStatus = "reviewed"
	RuleDraft    RuleStatus = "draft"
	RuleRejected RuleStatus = "rejected" // kept so the LLM does not regenerate it; never applied
)

// Rule describes when a vulnerable package is actually exploitable. YAML on disk (rules/*.yaml), JSON in the DB.
type Rule struct {
	ID            string            `json:"id" yaml:"id"`       // usually the CVE ID
	Vulns         []string          `json:"vulns" yaml:"vulns"` // CVE/GHSA IDs this rule covers
	Title         string            `json:"title" yaml:"title"`
	Packages      []PackageSelector `json:"packages" yaml:"packages"`                               // finding must match one selector
	Facts         []string          `json:"facts" yaml:"facts"`                                     // facts the expressions read; any missing -> conditions_unknown
	FactRequests  []FactRequest     `json:"fact_requests,omitempty" yaml:"fact_requests,omitempty"` // parametrised facts to request from agents
	ExploitableIf string            `json:"exploitable_if" yaml:"exploitable_if"`                   // CEL, bool
	NotAffectedIf string            `json:"not_affected_if,omitempty" yaml:"not_affected_if,omitempty"`
	Explanation   string            `json:"explanation" yaml:"explanation"` // why the conditions matter, shown in reports
	Fix           Fix               `json:"fix" yaml:"fix"`
	Status        RuleStatus        `json:"status" yaml:"status"`
	Source        string            `json:"source" yaml:"source"` // builtin | user | llm:<model>
	References    []string          `json:"references,omitempty" yaml:"references,omitempty"`
}

// PackageSelector matches a finding's package. Empty Type matches any type.
type PackageSelector struct {
	Name string `json:"name" yaml:"name"`
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
}

// Fix is the remediation advice attached to a rule.
type Fix struct {
	Upgrade    string `json:"upgrade,omitempty" yaml:"upgrade,omitempty"`       // generic upgrade advice; the server also derives a package-manager command
	Mitigation string `json:"mitigation,omitempty" yaml:"mitigation,omitempty"` // config change that removes the condition
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

// EventKind is what changed for a finding.
type EventKind string

const (
	EventExploitable     EventKind = "exploitable"      // new finding, or verdict changed to exploitable
	EventUnknownCritical EventKind = "unknown_critical" // conditions_unknown AND (KEV or severity critical)
	EventResolved        EventKind = "resolved"         // a previously notified finding is gone or no longer exploitable

	// Health events carry no finding (Event.Finding is zero) and a human text in Event.Detail.
	EventAgentSilent   EventKind = "agent_silent"   // a host stopped checking in (Host empty: aggregated, see Detail)
	EventAgentBack     EventKind = "agent_back"     // a silent host checked in again
	EventFeedStale     EventKind = "feed_stale"     // vulnerability DB is too old or cannot be refreshed
	EventFeedOK        EventKind = "feed_ok"        // the vulnerability DB recovered
	EventPipelineError EventKind = "pipeline_error" // matching keeps failing for a host
)

// IsHealth reports whether k is a health event (not about a finding).
func (k EventKind) IsHealth() bool {
	switch k {
	case EventAgentSilent, EventAgentBack, EventFeedStale, EventFeedOK, EventPipelineError:
		return true
	}
	return false
}

// Event is produced by the pipeline and consumed by notifiers.
type Event struct {
	Kind    EventKind `json:"kind"`
	Finding Finding   `json:"finding"`
	Host    Host      `json:"host"`
	Detail  string    `json:"detail,omitempty"` // human text of health events
	Rule    *Rule     `json:"rule,omitempty"`
	FixCmd  string    `json:"fix_cmd,omitempty"` // concrete command for this host's package manager
	WebURL  string    `json:"web_url,omitempty"` // link to the finding in the web UI
}

// ServerLevel reports whether the event is routed to the operations rooms instead of the rooms of
// the host's labels: feed and pipeline events, and aggregated host events (no host).
func (e Event) ServerLevel() bool {
	switch e.Kind {
	case EventFeedStale, EventFeedOK, EventPipelineError:
		return true
	case EventAgentSilent, EventAgentBack:
		return e.Host.ID == ""
	}
	return false
}
