// Package rules implements the Panoptes rule engine: loading, validation and
// CEL-based evaluation of exploitability rules (docs/contracts.md section 4).
package rules

import "strings"

// FactType is the declared type of a catalog fact.
type FactType string

// Fact types used in the catalog (docs/contracts.md section 3).
const (
	TString     FactType = "string"
	TBool       FactType = "bool"
	TStringList FactType = "list<string>"
	TIntList    FactType = "list<int>"
	TStringMap  FactType = "map<string,string>"
	TMapOfList  FactType = "map<string,list<string>>"
	TObjectList FactType = "list<map>"
)

// FileMatchPrefix is the prefix of parametrised file.match facts.
const FileMatchPrefix = "file.match:"

// factCatalog is the hard-coded fact catalog from docs/contracts.md section 3.
var factCatalog = map[string]FactType{
	"os.id":             TString,
	"os.version_id":     TString,
	"os.libc":           TString,
	"os.libc_version":   TString,
	"kernel.release":    TString,
	"kernel.modules":    TStringList,
	"kernel.sysctl":     TStringMap,
	"services.active":   TStringList,
	"sockets.listening": TObjectList,
	"sockets.ports":     TIntList,
	"sshd.installed":    TBool,
	"sshd.version":      TString,
	"sshd.config":       TStringMap,
	"nginx.installed":   TBool,
	"nginx.version":     TString,
	"nginx.modules":     TStringList,
	"nginx.directives":  TMapOfList,
	"nginx.http2":       TBool,
	"apache.installed":  TBool,
	"apache.version":    TString,
	"apache.modules":    TStringList,
	"apache.http2":      TBool,
	"php.installed":     TBool,
	"php.version":       TString,
	"php.sapi":          TStringList,
	"php.ini":           TStringMap,
	"openssl.version":   TString,
	"docker.installed":  TBool,
	"docker.version":    TString,
	"docker.containers": TObjectList,
	"runc.version":      TString,
	"sudo.version":      TString,
}

// FactTypeOf returns the catalog type of a fact name. Names of the form
// "file.match:<id>" have type list<string>.
func FactTypeOf(name string) (FactType, bool) {
	if strings.HasPrefix(name, FileMatchPrefix) && len(name) > len(FileMatchPrefix) {
		return TStringList, true
	}
	t, ok := factCatalog[name]
	return t, ok
}

// CatalogFacts returns the names of all fixed catalog facts (not file.match:*).
func CatalogFacts() []string {
	out := make([]string, 0, len(factCatalog))
	for k := range factCatalog {
		out = append(out, k)
	}
	return out
}
