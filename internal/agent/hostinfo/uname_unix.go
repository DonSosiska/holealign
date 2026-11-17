//go:build unix

package hostinfo

import "golang.org/x/sys/unix"

// kernelRelease is the equivalent of `uname -r`.
func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	n := 0
	for n < len(u.Release) && u.Release[n] != 0 {
		n++
	}
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(u.Release[i])
	}
	return string(b)
}
