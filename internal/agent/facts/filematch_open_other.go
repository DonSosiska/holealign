//go:build !linux

package facts

import "io/fs"

// safeOpen is nil off Linux: the portable fallback opens through Env.FS.
var safeOpen func(physical string) (fs.File, error)
