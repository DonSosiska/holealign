package rules

import (
	"net/url"
	"path"
	"strings"

	"github.com/DonSosiska/panoptes/internal/model"
)

// SourceOf returns the source package of a finding: the "upstream" qualifier of its PURL without
// version, or the binary package name when there is none.
//
// Syft sets the qualifier for deb ("<source>@<version>" or "<source>"), apk (the origin package)
// and arch (the base package). For rpm it holds the source RPM file name
// ("openssl-3.0.7-27.el9.src.rpm"); that is reduced to the package name ("openssl").
func SourceOf(purl, name string) string {
	if i := strings.IndexByte(purl, '?'); i >= 0 {
		if q, err := url.ParseQuery(purl[i+1:]); err == nil {
			up := q.Get("upstream")
			if j := strings.IndexByte(up, '@'); j >= 0 {
				up = up[:j]
			}
			if strings.HasSuffix(up, ".rpm") {
				up = strings.TrimSuffix(strings.TrimSuffix(up, ".rpm"), ".src")
				for k := 0; k < 2; k++ { // drop release and version
					if j := strings.LastIndexByte(up, '-'); j > 0 {
						up = up[:j]
					}
				}
			}
			if up != "" {
				return up
			}
		}
	}
	return name
}

// SelectorMatches reports whether any selector matches a package with the given binary name,
// source package name and type. A name selector is a glob over the binary name, a source
// selector an exact match on the source package.
func SelectorMatches(sels []model.PackageSelector, name, source, typ string) bool {
	for _, s := range sels {
		if s.Type != "" && s.Type != typ {
			continue
		}
		if s.Source != "" {
			if s.Name == "" && s.Source == source {
				return true
			}
			continue
		}
		if ok, err := path.Match(s.Name, name); err == nil && ok {
			return true
		}
	}
	return false
}
