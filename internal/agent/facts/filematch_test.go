package facts

import (
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
)

const modeSymlink = fs.ModeSymlink

// linkMapFS adds symbolic link support to fstest.MapFS: an entry with
// Mode&ModeSymlink set is a link whose target is the entry's Data.
type linkMapFS struct {
	fstest.MapFS
}

// mapInfo describes a MapFS entry itself (symlinks are not followed).
type mapInfo struct {
	name string
	f    *fstest.MapFile
}

func (i mapInfo) Name() string       { return path.Base(i.name) }
func (i mapInfo) Size() int64        { return int64(len(i.f.Data)) }
func (i mapInfo) Mode() fs.FileMode  { return i.f.Mode }
func (i mapInfo) ModTime() time.Time { return i.f.ModTime }
func (i mapInfo) IsDir() bool        { return i.f.Mode.IsDir() }
func (i mapInfo) Sys() any           { return i.f.Sys }

func (m linkMapFS) Lstat(name string) (fs.FileInfo, error) {
	if f, ok := m.MapFS[name]; ok && f != nil {
		return mapInfo{name: name, f: f}, nil
	}
	return fs.Stat(m.MapFS, name) // synthesized directories
}

func (m linkMapFS) ReadLink(name string) (string, error) {
	f, ok := m.MapFS[name]
	if !ok || f.Mode&fs.ModeSymlink == 0 {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	return string(f.Data), nil
}

func fileMatchFS() linkMapFS {
	return linkMapFS{fstest.MapFS{
		"etc/nginx/conf.d/app.conf": {Data: []byte("server {\n  proxy_pass http://127.0.0.1:8080;\n  password = hunter2\n}\n"), Mode: 0o644},
		"etc/evil":                  {Data: []byte("/root/.ssh/id_rsa"), Mode: fs.ModeSymlink},
		"etc/ok-link":               {Data: []byte("nginx/conf.d/app.conf"), Mode: fs.ModeSymlink},
		"etc/abs-ok":                {Data: []byte("/etc/nginx/conf.d/app.conf"), Mode: fs.ModeSymlink},
		"etc/dangling":              {Data: []byte("/etc/does-not-exist"), Mode: fs.ModeSymlink},
		"root/.ssh/id_rsa":          {Data: []byte("PRIVATE KEY MATERIAL"), Mode: 0o644},
		"opt/app/conf/app.yml":      {Data: []byte("name: demo\n"), Mode: 0o644},
		"opt/app/data/x.yml":        {Data: []byte("name: data\n"), Mode: 0o644},
		"usr/local/etc/a.conf":      {Data: []byte("listen 8443\n"), Mode: 0o644},
		"home/u/.bashrc":            {Data: []byte("alias x=y\n"), Mode: 0o644},
	}}
}

func TestEvalFileMatch(t *testing.T) {
	env := &Env{FS: fileMatchFS()}
	tests := []struct {
		name    string
		path    string
		pattern string
		want    []string
		ok      bool
	}{
		{
			name: "allowed glob with masking", path: "/etc/nginx/conf.d/*.conf", pattern: "proxy_pass|password",
			want: []string{
				"/etc/nginx/conf.d/app.conf:proxy_pass http://127.0.0.1:8080;",
				"/etc/nginx/conf.d/app.conf:password = ***",
			}, ok: true,
		},
		{name: "dot dot traversal rejected", path: "/etc/../root/.ssh/id_rsa", pattern: ".", ok: false},
		{name: "absolute outside roots rejected", path: "/root/.ssh/id_rsa", pattern: ".", ok: false},
		{name: "home rejected", path: "/home/u/.bashrc", pattern: ".", ok: false},
		{name: "relative path rejected", path: "etc/nginx/conf.d/app.conf", pattern: ".", ok: false},
		{name: "symlink escaping to /root rejected", path: "/etc/evil", pattern: ".", ok: false},
		{name: "dangling symlink rejected", path: "/etc/dangling", pattern: ".", ok: false},
		{
			name: "symlink inside allowed root followed (relative)", path: "/etc/ok-link", pattern: "proxy_pass",
			want: []string{"/etc/ok-link:proxy_pass http://127.0.0.1:8080;"}, ok: true,
		},
		{
			name: "opt conf allowed", path: "/opt/app/conf/*.yml", pattern: ".",
			want: []string{"/opt/app/conf/app.yml:name: demo"}, ok: true,
		},
		{name: "opt data not allowed", path: "/opt/app/data/*.yml", pattern: ".", ok: false},
		{
			name: "usr local etc allowed", path: "/usr/local/etc/*.conf", pattern: "listen",
			want: []string{"/usr/local/etc/a.conf:listen 8443"}, ok: true,
		},
		{name: "no file matched is unknown", path: "/etc/nothing/*.conf", pattern: ".", ok: false},
		{name: "invalid RE2 rejected", path: "/etc/nginx/conf.d/app.conf", pattern: "(", ok: false},
		{name: "empty pattern rejected", path: "/etc/nginx/conf.d/app.conf", pattern: "", ok: false},
		{name: "pattern over 512 chars rejected", path: "/etc/nginx/conf.d/app.conf", pattern: strings.Repeat("a", 513), ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := model.FactRequest{
				Name: "file.match:t", Collector: "file.match",
				Params: map[string]string{"path": tc.path, "pattern": tc.pattern},
			}
			got, ok := evalFileMatch(t.Context(), env, req)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (lines %v)", ok, tc.ok, got)
			}
			if ok && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("lines = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveSymlinks(t *testing.T) {
	fsys := fileMatchFS()
	tests := []struct {
		name, in, want string
		wantErr        bool
	}{
		{"relative link", "/etc/ok-link", "/etc/nginx/conf.d/app.conf", false},
		{"absolute link", "/etc/abs-ok", "/etc/nginx/conf.d/app.conf", false},
		{"link escaping to /root", "/etc/evil", "/root/.ssh/id_rsa", false},
		{"dangling link", "/etc/dangling", "", true},
		{"plain file", "/etc/nginx/conf.d/app.conf", "/etc/nginx/conf.d/app.conf", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSymlinks(fsys, tc.in, 0)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("resolved = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEvalFileMatchLimits(t *testing.T) {
	many := fstest.MapFS{}
	for i := 0; i < 60; i++ {
		many[fmt.Sprintf("etc/many/f%02d.conf", i)] = &fstest.MapFile{Data: []byte("hit\n"), Mode: 0o644}
	}
	env := &Env{FS: linkMapFS{many}}
	got, ok := evalFileMatch(t.Context(), env, model.FactRequest{Collector: "file.match", Name: "file.match:n",
		Params: map[string]string{"path": "/etc/many/*.conf", "pattern": "hit"}})
	if !ok || len(got) != fmMaxFiles {
		t.Errorf("file cap: got %d lines (ok=%v), want %d", len(got), ok, fmMaxFiles)
	}

	lines := fstest.MapFS{}
	for i := 0; i < 50; i++ {
		lines[fmt.Sprintf("etc/lines/f%02d.conf", i)] = &fstest.MapFile{Data: []byte(strings.Repeat("hit\n", 5)), Mode: 0o644}
	}
	env = &Env{FS: linkMapFS{lines}}
	got, ok = evalFileMatch(t.Context(), env, model.FactRequest{Collector: "file.match", Name: "file.match:n",
		Params: map[string]string{"path": "/etc/lines/*.conf", "pattern": "hit"}})
	if !ok || len(got) != fmMaxLines {
		t.Errorf("line cap: got %d lines (ok=%v), want %d", len(got), ok, fmMaxLines)
	}

	big := fstest.MapFS{
		"etc/big.conf": {Data: []byte(strings.Repeat("a", fmMaxFileBytes) + "\nhit-late\n"), Mode: 0o644},
	}
	env = &Env{FS: linkMapFS{big}}
	got, ok = evalFileMatch(t.Context(), env, model.FactRequest{Collector: "file.match", Name: "file.match:n",
		Params: map[string]string{"path": "/etc/big.conf", "pattern": "hit-late"}})
	if !ok || len(got) != 0 {
		t.Errorf("1 MiB cap: got %v (ok=%v), want no lines", got, ok)
	}
}

func TestMaskSecrets(t *testing.T) {
	tests := map[string]string{
		"password = hunter2":           "password = ***",
		"Token: abc123":                "Token: ***",
		"secret=xyz":                   "secret=***",
		"auth_basic off;":              "auth_basic off;",
		"ssl_certificate_key /etc/x.k": "ssl_certificate_key /etc/x.k",
		"proxy_pass http://x":          "proxy_pass http://x",
	}
	for in, want := range tests {
		if got := maskSecrets(in); got != want {
			t.Errorf("maskSecrets(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSelectFileMatchRequests(t *testing.T) {
	var reqs []model.FactRequest
	reqs = append(reqs, model.FactRequest{Name: "file.match:bad", Collector: "shell"})
	reqs = append(reqs, model.FactRequest{Name: "file.match:dup", Collector: "file.match", Params: map[string]string{"path": "/etc/d", "pattern": "x"}})
	reqs = append(reqs, model.FactRequest{Name: "file.match:dup", Collector: "file.match", Params: map[string]string{"path": "/etc/d", "pattern": "x"}})
	for i := 0; i < 50; i++ {
		reqs = append(reqs, model.FactRequest{Name: fmt.Sprintf("file.match:r%d", i), Collector: "file.match", Params: map[string]string{"path": fmt.Sprintf("/etc/r%d", i), "pattern": "x"}})
	}
	got := selectFileMatchRequests(reqs)
	if len(got) != fmMaxRequests {
		t.Fatalf("selected %d requests, want %d", len(got), fmMaxRequests)
	}
	for _, r := range got {
		if r.Name == "file.match:bad" {
			t.Error("unknown collector must be ignored")
		}
	}
	if got[0].Name != "file.match:dup" {
		t.Errorf("first selected = %q", got[0].Name)
	}
}
