// Package rulesbot holds the logic behind "holealign-server rules candidates|draft", the commands
// a rules repository's CI bot uses to pick CVEs worth a rule and to draft a rule plus tests.
package rulesbot

import (
	"fmt"
	"math"
	"strings"
)

// CVSS3Score computes the CVSS v3.0/v3.1 base score from a vector string such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". The v3.1 round-up function is used for both
// versions (the two differ only in rare floating point edge cases).
func CVSS3Score(vector string) (float64, error) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 9 || (parts[0] != "CVSS:3.1" && parts[0] != "CVSS:3.0") {
		return 0, fmt.Errorf("not a CVSS v3 vector: %q", vector)
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, fmt.Errorf("bad metric %q", p)
		}
		if _, dup := m[k]; dup {
			return 0, fmt.Errorf("duplicate metric %q", k)
		}
		m[k] = v
	}
	pick := func(key string, tbl map[string]float64) (float64, error) {
		v, ok := tbl[m[key]]
		if !ok {
			return 0, fmt.Errorf("metric %s: bad or missing value %q", key, m[key])
		}
		return v, nil
	}
	if m["S"] != "C" && m["S"] != "U" {
		return 0, fmt.Errorf("metric S: bad or missing value %q", m["S"])
	}
	changed := m["S"] == "C"
	prTbl := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		prTbl = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	av, err := pick("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if err != nil {
		return 0, err
	}
	ac, err := pick("AC", map[string]float64{"L": 0.77, "H": 0.44})
	if err != nil {
		return 0, err
	}
	pr, err := pick("PR", prTbl)
	if err != nil {
		return 0, err
	}
	ui, err := pick("UI", map[string]float64{"N": 0.85, "R": 0.62})
	if err != nil {
		return 0, err
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, err := pick("C", cia)
	if err != nil {
		return 0, err
	}
	i, err := pick("I", cia)
	if err != nil {
		return 0, err
	}
	a, err := pick("A", cia)
	if err != nil {
		return 0, err
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, nil
	}
	expl := 8.22 * av * ac * pr * ui
	if changed {
		return roundUp(math.Min(1.08*(impact+expl), 10)), nil
	}
	return roundUp(math.Min(impact+expl, 10)), nil
}

// roundUp is the CVSS v3.1 Roundup function (smallest one-decimal number >= x).
func roundUp(x float64) float64 {
	n := int(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

// Rating maps a base score to the qualitative CVSS rating.
func Rating(score float64) string {
	switch {
	case score >= 9:
		return "Critical"
	case score >= 7:
		return "High"
	case score >= 4:
		return "Medium"
	case score > 0:
		return "Low"
	}
	return "None"
}
