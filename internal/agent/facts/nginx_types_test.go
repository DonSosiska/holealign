package facts

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseNginxDirectivesSkipsTypesBlocks(t *testing.T) {
	dirs := parseNginxDirectives(fixture(t, "nginx_T_types.txt"))

	// MIME entries from both types blocks must not appear as directives.
	for _, key := range []string{"text/html", "application/json", "application/javascript", "text/css", "text/plain", "types"} {
		if _, ok := dirs[key]; ok {
			t.Errorf("types block leaked into directives: %q = %q", key, dirs[key])
		}
	}
	for key := range dirs {
		if strings.Contains(key, "/") {
			t.Errorf("unexpected MIME-like key %q", key)
		}
	}

	// Directives around and after the block are still parsed.
	tests := []struct {
		name string
		want []string
	}{
		{"server_names_hash_bucket_size", []string{"64"}},
		{"http2", []string{"on"}},
		{"default_type", []string{"application/octet-stream"}},
		{"proxy_pass", []string{"http://127.0.0.1:8080"}},
		{"server_name", []string{"example.com"}},
	}
	for _, tc := range tests {
		if got := dirs[tc.name]; !reflect.DeepEqual(got, tc.want) {
			t.Errorf("directive %s = %q, want %q", tc.name, got, tc.want)
		}
	}

	// Header lines printed by nginx -T are not directives.
	for key := range dirs {
		if strings.HasPrefix(key, "#") || strings.HasPrefix(key, "configuration") || strings.HasPrefix(key, "nginx:") {
			t.Errorf("header line leaked into directives: %q", key)
		}
	}
	if !nginxHTTP2(dirs) {
		t.Error("http2 on inside http block should still be detected")
	}
}
