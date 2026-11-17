package web

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLocalHostBadge(t *testing.T) {
	e := newEnv(t, false)
	c := e.session("admin")
	own := e.seedHost("srv-local", "server")
	other := e.seedHost("srv-remote", "prod")
	for _, p := range []string{"/hosts", "/hosts/" + own.ID} {
		if body := e.do("GET", p, nil, c).Body.String(); strings.Contains(body, "local (built-in)") {
			t.Fatalf("%s shows the badge before the host is marked local", p)
		}
	}
	if err := e.st.KVSet(context.Background(), "local_host", own.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	list := e.do("GET", "/hosts", nil, c).Body.String()
	if n := strings.Count(list, "local (built-in)"); n != 1 {
		t.Fatalf("hosts list shows the badge %d times, want 1", n)
	}
	if !strings.Contains(e.do("GET", "/hosts/"+own.ID, nil, c).Body.String(), "local (built-in)") {
		t.Fatal("host page of the local host has no badge")
	}
	if strings.Contains(e.do("GET", "/hosts/"+other.ID, nil, c).Body.String(), "local (built-in)") {
		t.Fatal("badge on a remote host")
	}
}
