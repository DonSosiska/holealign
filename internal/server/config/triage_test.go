package config

import "testing"

func TestTriageEPSSThreshold(t *testing.T) {
	none := func(string) (string, bool) { return "", false }
	cfg, err := load("", none)
	if err != nil || cfg.Triage.EPSSThreshold != 0.1 {
		t.Fatalf("default: %v %+v", err, cfg)
	}
	env := func(v string) func(string) (string, bool) {
		return func(k string) (string, bool) {
			if k == "PANOPTES_TRIAGE_EPSS_THRESHOLD" {
				return v, true
			}
			return "", false
		}
	}
	cfg, err = load("", env("0.25"))
	if err != nil || cfg.Triage.EPSSThreshold != 0.25 {
		t.Fatalf("env: %v %+v", err, cfg)
	}
	for _, bad := range []string{"1.5", "-0.1", "abc", "NaN"} {
		if _, err := load("", env(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
