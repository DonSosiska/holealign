//go:build !unix

package hostinfo

func kernelRelease() string { return "" }
