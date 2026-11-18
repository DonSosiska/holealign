//go:build unix

package main

import "syscall"

// restrictUmask makes every file and directory the server creates private to its user.
func restrictUmask() { syscall.Umask(0o077) }
