package facts

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestFileMatchDenylistCredentialLocations(t *testing.T) {
	for _, p := range []string{
		"/etc/apt/auth.conf", "/etc/apt/auth.conf.d/90-private", "/etc/apt/auth.conf.d",
		"/opt/tomcat/conf/tomcat-users.xml", "/etc/tomcat9/tomcat-users.xml", "/usr/local/etc/tomcat/Tomcat-Users.xml",
		"/etc/hostapd/hostapd.conf", "/etc/squid/passwords", "/etc/gitlab/gitlab.rb",
		"/etc/phpmyadmin/config-db.php", "/etc/phpmyadmin/config.inc.php",
		"/etc/msmtprc", "/etc/nagios/resource.cfg", "/etc/ssmtp/ssmtp.conf",
		"/etc/my.cnf", "/etc/my.cnf.d/server.cnf", "/etc/redis.conf", "/etc/containers/auth.json",
		"/etc/snmp/snmpd.conf", "/etc/tomcat9/server.xml", "/opt/tomcat/conf/server.xml",
		"/etc/gitlab-runner/config.toml", "/etc/nslcd.conf", "/etc/pam_ldap.conf", "/etc/libnss-ldap.conf",
	} {
		if !fmDenied(p) {
			t.Errorf("%s should be denied", p)
		}
	}
	for _, p := range []string{"/etc/apt/sources.list", "/etc/apt/apt.conf.d/20auto", "/etc/squid/squid.conf", "/etc/nagios/nagios.cfg", "/etc/tomcat9/web.xml"} {
		if fmDenied(p) {
			t.Errorf("%s should be allowed", p)
		}
	}
}

// strLists extracts the string literals of the composite literal assigned to the package-level
// variable name in file: [][]string becomes one joined entry per row, []string one per element.
func strLists(t *testing.T, file, name string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != name || len(vs.Values) != 1 {
			return true
		}
		found = true
		cl := vs.Values[0].(*ast.CompositeLit)
		for _, e := range cl.Elts {
			switch x := e.(type) {
			case *ast.BasicLit:
				s, _ := strconv.Unquote(x.Value)
				out = append(out, s)
			case *ast.CompositeLit:
				var row []string
				for _, c := range x.Elts {
					s, _ := strconv.Unquote(c.(*ast.BasicLit).Value)
					row = append(row, s)
				}
				out = append(out, strings.Join(row, "/"))
			}
		}
		return false
	})
	if !found {
		t.Fatalf("%s not found in %s", name, file)
	}
	return out
}

// The agent keeps its own copy of the server's file.match denylist. Both the component-pattern
// lists and the absolute path lists must stay identical so the agent enforces the full policy
// independently of the server.
func TestFileMatchDenylistInSyncWithServer(t *testing.T) {
	const server = "../../server/rules/filematch.go"
	srvPatterns := strLists(t, server, "denyPatterns")
	agentPatterns := strLists(t, "filematch.go", "fmDenyPatterns")
	if !reflect.DeepEqual(srvPatterns, agentPatterns) {
		t.Errorf("deny pattern lists differ:\nserver: %v\nagent:  %v", srvPatterns, agentPatterns)
	}
	srvPaths := strLists(t, server, "denyPaths")
	agentPaths := strLists(t, "filematch.go", "fmDenyPaths")
	if !reflect.DeepEqual(srvPaths, agentPaths) {
		t.Errorf("deny path lists differ:\nserver: %v\nagent:  %v", srvPaths, agentPaths)
	}
}
