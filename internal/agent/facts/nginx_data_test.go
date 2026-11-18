package facts

import (
	"strings"
	"testing"
)

func TestParseNginxDirectivesSkipsDataBlocks(t *testing.T) {
	conf := `
http {
    map $http_x_api_key $client {
        default 0;
        "k9Zx3fAbCdEf1234567" client1;
        "sk_live_abcdef012345" client2;
    }
    geo $remote_addr $blocked {
        default 0;
        "Bearer xxx" 1;
        10.0.0.0/8 1;
    }
    split_clients "${remote_addr}AAA" $variant {
        50% "k9Zx3fAbCdEf1234567";
        * "";
    }
    server { listen 80; server_name example.com; }
}
`
	dirs := parseNginxDirectives([]byte(conf))
	for key := range dirs {
		for _, bad := range []string{"k9Zx", "sk_live", "Bearer", "default", "10.0.0.0", "50%"} {
			if strings.Contains(key, bad) {
				t.Errorf("data leaked as directive key %q", key)
			}
		}
	}
	for _, v := range dirs {
		for _, s := range v {
			if strings.Contains(s, "client1") || strings.Contains(s, "k9Zx") {
				t.Errorf("data leaked as value %q", s)
			}
		}
	}
	if _, ok := dirs["map"]; !ok {
		t.Error("map opener must be kept")
	}
	if got := dirs["server_name"]; len(got) != 1 || got[0] != "example.com" {
		t.Errorf("directives after data blocks lost: %v", got)
	}
	if got := dirs["listen"]; len(got) != 1 {
		t.Errorf("listen after data blocks: %v", got)
	}
}

func TestParseNginxDirectivesMasksSecretKeys(t *testing.T) {
	// A statement outside any known data block whose first token is a secret.
	conf := `"k9Zx3fAbCdEf1234567" a; "sk_live_abcdef012345" b; "Bearer xxx" c; worker_processes 4;`
	dirs := parseNginxDirectives([]byte(conf))
	for key := range dirs {
		for _, bad := range []string{"k9Zx", "sk_live_abc", "Bearer"} {
			if strings.Contains(key, bad) {
				t.Errorf("secret kept in directive key %q", key)
			}
		}
	}
	if len(dirs["worker_processes"]) != 1 {
		t.Errorf("normal directive lost: %v", dirs)
	}
}
