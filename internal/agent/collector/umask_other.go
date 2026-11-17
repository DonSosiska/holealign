//go:build !unix

package collector

func setUmask(m int) int { return m }
