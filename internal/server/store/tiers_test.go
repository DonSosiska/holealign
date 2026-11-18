package store

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
)

func tf(pkg, vuln string, v model.Verdict, sev, fix string, epss float64, kev bool) model.Finding {
	return model.Finding{Target: "host", TargetKind: model.TargetHost, PackageName: pkg, PackageVer: "1", PackageType: "deb",
		VulnID: vuln, Severity: sev, FixState: fix, EPSS: epss, KEV: kev, CVSS: 5, Verdict: v}
}

func tierIDs(t *testing.T, s *SQLite, tier string) []string {
	t.Helper()
	list, _, err := s.ListFindings(context.Background(), FindingFilter{Tier: tier, EPSSThreshold: 0.1, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range list {
		ids = append(ids, f.VulnID)
	}
	sort.Strings(ids)
	return ids
}

func TestTierBranches(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	h := enroll(t, s, "m1")
	U, X, NE := model.VerdictConditionsUnknown, model.VerdictExploitable, model.VerdictNotExploitable
	found := []model.Finding{
		tf("a", "CVE-1-KEV", U, "Low", "not-fixed", 0, true),
		tf("a", "CVE-2-EPSSEQ", U, "Low", "not-fixed", 0.1, false),
		tf("a", "CVE-3-EPSSBELOW", U, "Low", "not-fixed", 0.0999, false),
		tf("a", "CVE-4-CRITFIXED", U, "Critical", "fixed", 0, false),
		tf("a", "CVE-5-HIGHFIXED", U, "high", "fixed", 0, false),
		tf("a", "CVE-6-HIGHNOTFIXED", U, "High", "not-fixed", 0, false),
		tf("a", "CVE-7-MEDFIXED", U, "Medium", "fixed", 0, false),
		tf("a", "CVE-8-EXPL", X, "Low", "unknown", 0, false),
		tf("a", "CVE-9-NE", NE, "Critical", "fixed", 0.9, true),
	}
	if _, err := s.ApplyHostFindings(ctx, h.ID, found, time.Now()); err != nil {
		t.Fatal(err)
	}
	att := tierIDs(t, s, TierAttention)
	want := []string{"CVE-1-KEV", "CVE-2-EPSSEQ", "CVE-4-CRITFIXED", "CVE-5-HIGHFIXED", "CVE-8-EXPL"}
	if len(att) != len(want) {
		t.Fatalf("attention = %v, want %v", att, want)
	}
	for i := range want {
		if att[i] != want[i] {
			t.Fatalf("attention = %v, want %v", att, want)
		}
	}
	bg := tierIDs(t, s, TierBackground)
	wantBG := []string{"CVE-3-EPSSBELOW", "CVE-6-HIGHNOTFIXED", "CVE-7-MEDFIXED", "CVE-9-NE"}
	if len(bg) != len(wantBG) {
		t.Fatalf("background = %v, want %v", bg, wantBG)
	}
	for i := range wantBG {
		if bg[i] != wantBG[i] {
			t.Fatalf("background = %v, want %v", bg, wantBG)
		}
	}
	// a higher threshold removes the EPSS-boundary finding from attention
	list, _, _ := s.ListFindings(ctx, FindingFilter{Tier: TierAttention, EPSSThreshold: 0.5, Limit: 100})
	for _, f := range list {
		if f.VulnID == "CVE-2-EPSSEQ" {
			t.Fatal("EPSS 0.1 must be background at threshold 0.5")
		}
	}
	// resolved findings are in no tier
	if _, err := s.ApplyHostFindings(ctx, h.ID, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := tierIDs(t, s, TierBackground); len(got) != 0 {
		t.Fatalf("resolved in background: %v", got)
	}
}

func TestGroupsAndCounts(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	h1, h2 := enroll(t, s, "m1", "prod"), enroll(t, s, "m2")
	U := model.VerdictConditionsUnknown
	found := []model.Finding{
		tf("openssh-client", "CVE-2024-6387", U, "High", "fixed", 0, false),
		tf("openssh-server", "CVE-2024-6387", U, "Critical", "fixed", 0.5, false),
		tf("openssh-sftp-server", "CVE-2024-6387", U, "High", "fixed", 0, false),
		tf("libc6", "CVE-2020-1", U, "Low", "wont-fix", 0, false),
		tf("libc-bin", "CVE-2020-1", U, "Low", "wont-fix", 0, false),
		tf("x", "CVE-2020-2", model.VerdictExploitable, "Low", "", 0, false),
		tf("y", "CVE-2020-2", U, "Low", "", 0, false),
		tf("z", "CVE-2020-3", model.VerdictNotExploitable, "Low", "", 0, false),
	}
	if _, err := s.ApplyHostFindings(ctx, h1.ID, found, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyHostFindings(ctx, h2.ID, found[:1], time.Now()); err != nil {
		t.Fatal(err)
	}
	total, per, err := s.CountByTier(ctx, 0.1)
	if err != nil {
		t.Fatal(err)
	}
	if c := per[h1.ID]; c != (TierCounts{Exploitable: 1, Attention: 1, Background: 1, NotExploitable: 1}) {
		t.Fatalf("host1 counts %+v", c)
	}
	if c := per[h2.ID]; c != (TierCounts{Attention: 1}) {
		t.Fatalf("host2 counts %+v", c)
	}
	if total != (TierCounts{Exploitable: 1, Attention: 2, Background: 1, NotExploitable: 1}) {
		t.Fatalf("total %+v", total)
	}

	groups, n, err := s.ListFindingGroups(ctx, FindingFilter{HostID: h1.ID, Tier: TierAttention, EPSSThreshold: 0.1, Limit: 10})
	if err != nil || n != 2 || len(groups) != 2 {
		t.Fatalf("groups %v %d %v", groups, n, err)
	}
	if groups[0].VulnID != "CVE-2020-2" || groups[0].Verdict != model.VerdictExploitable || len(groups[0].Findings) != 2 {
		t.Fatalf("first group %+v", groups[0])
	}
	g := groups[1]
	if g.VulnID != "CVE-2024-6387" || len(g.Findings) != 3 || g.Severity != "Critical" || g.EPSS != 0.5 || !g.Attention {
		t.Fatalf("ssh group %+v", g)
	}
	// background groups: libc pair only (CVE-2020-3 is not-exploitable, also background by tier)
	groups, n, _ = s.ListFindingGroups(ctx, FindingFilter{HostID: h1.ID, Tier: TierBackground, EPSSThreshold: 0.1, Limit: 10})
	if n != 2 || len(groups) != 2 {
		t.Fatalf("background groups %d", n)
	}
	// untiered with paging
	groups, n, _ = s.ListFindingGroups(ctx, FindingFilter{Limit: 2, Offset: 2, EPSSThreshold: 0.1})
	if n != 5 || len(groups) != 2 {
		t.Fatalf("paging n=%d len=%d", n, len(groups))
	}
	// label filter keeps working on groups
	_, n, _ = s.ListFindingGroups(ctx, FindingFilter{Label: "prod", Limit: 50, EPSSThreshold: 0.1})
	if n != 4 {
		t.Fatalf("label groups %d", n)
	}
}
