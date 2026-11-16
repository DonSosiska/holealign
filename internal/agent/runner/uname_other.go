//go:build !unix

package runner

func kernelRelease() string { return "" }
