//go:build !unix

package facts

import "io/fs"

var nbOpen func(abs string) (fs.File, error)
