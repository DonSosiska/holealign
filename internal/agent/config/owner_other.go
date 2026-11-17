//go:build !unix

package config

import "os"

func matchOwner(*os.File, os.FileInfo) error { return nil }
