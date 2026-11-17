package store

import (
	"context"
	"strings"

	"github.com/DonSosiska/panoptes/internal/model"
)

// attentionSQL is the SQL of the attention tier for rows aliased f; it takes one argument, the EPSS
// threshold. Resolved rows never match.
func attentionSQL() string {
	return `(f.verdict='exploitable' OR (f.verdict='conditions_unknown' AND (f.kev=1 OR f.epss>=? OR ` +
		`(lower(f.severity) IN ('critical','high') AND f.fix_state='fixed'))))`
}

// findingWhere builds the WHERE clause shared by the listings. rowTier adds the per-row tier
// condition (ListFindings); grouped listings apply the tier in HAVING instead.
func findingWhere(fl FindingFilter, rowTier bool) (string, []any) {
	var where []string
	var args []any
	switch {
	case fl.Verdict != "":
		where = append(where, "f.verdict=?")
		args = append(args, string(fl.Verdict))
	case !fl.IncludeResolved:
		where = append(where, "f.verdict<>'resolved'")
	}
	if fl.HostID != "" {
		where = append(where, "f.host_id=?")
		args = append(args, fl.HostID)
	}
	if fl.KEV != nil {
		where = append(where, "f.kev=?")
		args = append(args, b2i(*fl.KEV))
	}
	if fl.VulnID != "" {
		where = append(where, "(f.vuln_id=? OR EXISTS (SELECT 1 FROM json_each(f.aliases) WHERE value=?))")
		args = append(args, fl.VulnID, fl.VulnID)
	}
	if fl.Label != "" {
		where = append(where, "EXISTS (SELECT 1 FROM hosts h, json_each(h.labels) WHERE h.id=f.host_id AND value=?)")
		args = append(args, fl.Label)
	}
	if rowTier {
		switch fl.Tier {
		case TierAttention:
			where = append(where, attentionSQL())
			args = append(args, fl.EPSSThreshold)
		case TierBackground:
			where = append(where, "(f.verdict<>'resolved' AND NOT "+attentionSQL()+")")
			args = append(args, fl.EPSSThreshold)
		}
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	return cond, args
}

func pageLimit(fl FindingFilter) int {
	switch {
	case fl.Limit <= 0:
		return 100
	case fl.Limit > 1000:
		return 1000
	}
	return fl.Limit
}

func (s *SQLite) ListFindings(ctx context.Context, fl FindingFilter) ([]model.Finding, int, error) {
	cond, args := findingWhere(fl, true)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings f`+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT ` + prefixCols("f", findingCols) + ` FROM findings f` + cond +
		` ORDER BY (f.verdict='exploitable') DESC, f.kev DESC, f.epss DESC, f.cvss DESC, f.id LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, q, append(args, pageLimit(fl), max(fl.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, f)
	}
	return out, total, rows.Err()
}

const verdictRankSQL = `CASE f.verdict WHEN 'exploitable' THEN 0 WHEN 'conditions_unknown' THEN 1
	WHEN 'affected_not_exploitable' THEN 2 WHEN 'not_affected' THEN 3 ELSE 4 END`

var verdictByRank = []model.Verdict{model.VerdictExploitable, model.VerdictConditionsUnknown,
	model.VerdictNotExploitable, model.VerdictNotAffected, model.VerdictResolved}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "negligible":
		return 1
	}
	return 0
}

func (s *SQLite) ListFindingGroups(ctx context.Context, fl FindingFilter) ([]FindingGroup, int, error) {
	cond, args := findingWhere(fl, false)
	having := ""
	switch fl.Tier {
	case TierAttention:
		having = " HAVING att=1"
	case TierBackground:
		having = " HAVING att=0 AND vr<4"
	}
	inner := `SELECT f.host_id AS host_id, f.vuln_id AS vuln_id, MIN(` + verdictRankSQL + `) AS vr, MAX(f.kev) AS kev,
		MAX(f.epss) AS epss, MAX(f.cvss) AS cvss, MAX(` + attentionSQL() + `) AS att
		FROM findings f` + cond + ` GROUP BY f.host_id, f.vuln_id` + having
	// the select-list threshold comes before the WHERE arguments
	allArgs := append([]any{fl.EPSSThreshold}, args...)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (`+inner+`)`, allArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, vuln_id, vr, kev, epss, cvss, att FROM (`+inner+`)
		ORDER BY (vr=0) DESC, att DESC, kev DESC, epss DESC, cvss DESC, host_id, vuln_id LIMIT ? OFFSET ?`,
		append(allArgs, pageLimit(fl), max(fl.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	var groups []FindingGroup
	for rows.Next() {
		var g FindingGroup
		var vr, kev, att int
		if err := rows.Scan(&g.HostID, &g.VulnID, &vr, &kev, &g.EPSS, &g.CVSS, &att); err != nil {
			rows.Close()
			return nil, 0, err
		}
		g.Verdict = verdictByRank[min(max(vr, 0), len(verdictByRank)-1)]
		g.KEV, g.Attention = kev != 0, att != 0
		groups = append(groups, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(groups) == 0 {
		return nil, total, nil
	}
	// members of the page's groups
	idx := map[[2]string]int{}
	var vals []string
	margs := append([]any(nil), args...)
	for i, g := range groups {
		idx[[2]string{g.HostID, g.VulnID}] = i
		vals = append(vals, "(?,?)")
		margs = append(margs, g.HostID, g.VulnID)
	}
	mcond := cond + " AND "
	if cond == "" {
		mcond = " WHERE "
	}
	mrows, err := s.db.QueryContext(ctx, `SELECT `+prefixCols("f", findingCols)+` FROM findings f`+mcond+
		`(f.host_id, f.vuln_id) IN (VALUES `+strings.Join(vals, ",")+`) ORDER BY f.package_name, f.package_version, f.id`, margs...)
	if err != nil {
		return nil, 0, err
	}
	defer mrows.Close()
	for mrows.Next() {
		f, err := scanFinding(mrows)
		if err != nil {
			return nil, 0, err
		}
		g := &groups[idx[[2]string{f.HostID, f.VulnID}]]
		g.Findings = append(g.Findings, f)
		if severityRank(f.Severity) > severityRank(g.Severity) {
			g.Severity = f.Severity
		}
	}
	return groups, total, mrows.Err()
}

func (s *SQLite) CountByTier(ctx context.Context, eps float64) (TierCounts, map[string]TierCounts, error) {
	var total TierCounts
	per := map[string]TierCounts{}
	rows, err := s.db.QueryContext(ctx, `SELECT host_id,
		SUM(ex=1), SUM(ex=0 AND att=1), SUM(ex=0 AND att=0 AND unk=1), SUM(ex=0 AND unk=0 AND ne=1), SUM(ex=0 AND unk=0 AND ne=0 AND na=1)
		FROM (SELECT f.host_id AS host_id, f.vuln_id AS vuln_id,
			MAX(f.verdict='exploitable') AS ex, MAX(f.verdict='conditions_unknown') AS unk,
			MAX(f.verdict='conditions_unknown' AND `+attentionSQL()+`) AS att,
			MAX(f.verdict='affected_not_exploitable') AS ne, MAX(f.verdict='not_affected') AS na
			FROM findings f WHERE f.verdict<>'resolved' GROUP BY f.host_id, f.vuln_id)
		GROUP BY host_id`, eps)
	if err != nil {
		return total, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h string
		var c TierCounts
		if err := rows.Scan(&h, &c.Exploitable, &c.Attention, &c.Background, &c.NotExploitable, &c.NotAffected); err != nil {
			return total, nil, err
		}
		per[h] = c
		total.Exploitable += c.Exploitable
		total.Attention += c.Attention
		total.Background += c.Background
		total.NotExploitable += c.NotExploitable
		total.NotAffected += c.NotAffected
	}
	return total, per, rows.Err()
}
