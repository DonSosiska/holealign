//go:build !unix

package collector

import "os"

func fileGID(os.FileInfo) (int, bool) { return 0, false }
