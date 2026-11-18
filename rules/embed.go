// Package shipped embeds the rules shipped with Holealign (the *.yaml files next to this file),
// so a server without a rules_dir still has them. They are the lowest rule layer.
package shipped

import "embed"

// FS holds the shipped rule files at its root.
//
//go:embed *.yaml
var FS embed.FS
