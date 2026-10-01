//go:build unix

package main

import (
	"os"
	"syscall"
)

// lockConfig takes an exclusive advisory lock on the lock file at path, so
// that two cairn processes do not interleave a read-modify-write of the
// config file. The returned function releases it.
func lockConfig(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil // closing releases the lock
}
