package rulesbot

import (
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var codeSpanR = regexp.MustCompile("``.*?``")

// outsideCode returns the Markdown of body that is not inside a fenced block or an inline code span.
func outsideCode(body string) string {
	var out []string
	in := false
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "```") {
			in = !in
			continue
		}
		if !in {
			out = append(out, codeSpanR.ReplaceAllString(l, ""))
		}
	}
	return strings.Join(out, "\n")
}

func TestPRBodyHostileTextIsInert(t *testing.T) {
	hostile := `[click](https://evil.example/x) ![img](https://evil.example/i.png) <https://evil.example/auto> ` +
		`@octocat @org/team <!-- hidden --> <script>x</script> **bold** www.evil.example`
	r := strings.Replace(reply(goodExpr, goodTests), `Needs root login enabled.`, strings.ReplaceAll(hostile, `"`, `'`), 1)
	r = strings.Replace(r, `OpenSSH root login issue`, `[title](https://evil.example/t) @title-mention`, 1)
	r = strings.Replace(r, `Upgrade openssh.`, "[up](https://evil.example/u) ``` @fix", 1)
	r = strings.Replace(r, `"name": "root login on"`, `"name": "[n](https://evil.example/n) @name | x"`, 1)
	res, err := Draft(context.Background(), opts(t, &fakeProv{replies: []string{r}}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.PRBody, "https://evil.example/x") {
		t.Fatalf("hostile text should still be shown (as code):\n%s", res.PRBody)
	}
	rest := outsideCode(res.PRBody)
	for _, bad := range []string{"evil", "@", "<!--", "<script", "![", "**bold"} {
		if strings.Contains(rest, bad) {
			t.Errorf("%q is interpretable Markdown in the body:\n%s", bad, rest)
		}
	}
	// The only links are the ones built from the candidate's own IDs.
	for _, m := range regexp.MustCompile(`\]\(([^)]*)\)`).FindAllStringSubmatch(rest, -1) {
		u := m[1]
		if !strings.HasPrefix(u, "https://osv.dev/vulnerability/CVE-2099-0100") && !strings.HasPrefix(u, "https://nvd.nist.gov/vuln/detail/CVE-2099-0100") &&
			!strings.HasPrefix(u, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2099-0100") {
			t.Errorf("unexpected link %q", u)
		}
	}
	// A fence in the text cannot close the block early: the surrounding fence is longer.
	if !strings.Contains(res.PRBody, "````\n") {
		t.Errorf("fence not widened:\n%s", res.PRBody)
	}
}

func TestPRBodyRuleScope(t *testing.T) {
	res, err := Draft(context.Background(), opts(t, &fakeProv{replies: []string{reply(goodExpr, goodTests)}}))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"### Rule scope", "vulns:\n  - CVE-2099-0100\n  - DEBIAN-CVE-2099-0100", "packages:\n  - source: openssh\n    type: deb"} {
		if !strings.Contains(res.PRBody, s) {
			t.Errorf("scope lacks %q:\n%s", s, res.PRBody)
		}
	}
}

func TestFilterAliases(t *testing.T) {
	cases := []struct {
		name string
		cve  string
		eco  string
		ids  []string
		want []string
	}{
		{"single CVE keeps own distro id and GHSA", "CVE-2024-1", "Debian:12",
			[]string{"DEBIAN-CVE-2024-0001", "CVE-2024-0001", "GHSA-abcd-1234-wxyz", "ALPINE-CVE-2024-0001", "junk [x](http://e)"},
			[]string{"DEBIAN-CVE-2024-0001", "GHSA-abcd-1234-wxyz"}},
		{"multi CVE record keeps only own", "CVE-2024-0001", "Debian:12",
			[]string{"DSA-1", "CVE-2024-0001", "CVE-2024-0002", "DEBIAN-CVE-2024-0002", "DEBIAN-CVE-2024-0001", "GHSA-abcd-1234-wxyz"},
			[]string{"DEBIAN-CVE-2024-0001"}},
		{"alpine", "CVE-2024-0001", "Alpine:v3.20", []string{"ALPINE-CVE-2024-0001", "DEBIAN-CVE-2024-0001"}, []string{"ALPINE-CVE-2024-0001"}},
		{"bad ghsa", "CVE-2024-0001", "Debian:12", []string{"GHSA-ABCD-1234-wxyz", "GHSA-abcd-1234"}, []string{}},
	}
	for _, tc := range cases {
		if tc.name == "single CVE keeps own distro id and GHSA" {
			tc.cve = "CVE-2024-0001"
		}
		got := FilterAliases(tc.cve, tc.eco, tc.ids, slog.Default())
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestToCandidateMultiCVERecord(t *testing.T) {
	raw := `{"id":"DEBIAN-CVE-2024-0001","aliases":["CVE-2024-0001","CVE-2024-0002","GHSA-abcd-1234-wxyz"],"database_specific":{"severity":"high"},
	  "affected":[{"package":{"name":"pkg","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2"}]}]}]}`
	var d osvDetail
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatal(err)
	}
	c, _, ok := toCandidate(&d, "pkg", "Debian:12", "deb", map[string]bool{})
	if !ok || c.Vuln != "CVE-2024-0001" || !reflect.DeepEqual(c.Aliases, []string{"DEBIAN-CVE-2024-0001"}) {
		t.Fatalf("candidate %+v", c)
	}
}
