//go:build !unix

package main

// lockConfig is a no-op where there is no flock: the write is still atomic,
// but two processes can lose each other's update.
func lockConfig(string) (func(), error) { return func() {}, nil }
