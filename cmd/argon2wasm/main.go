//go:build js && wasm

// Command argon2wasm compiles to WebAssembly and registers a single global
// JS function, cairnArgon2id, that derives a 32-byte Argon2id key from a
// password and salt. See internal/server/web/argon2.mjs for the loader that
// calls it, and the "Password stretching" section of
// design/e2e-wire-formats.md for the parameters it uses.
package main

import (
	"fmt"
	"syscall/js"

	"golang.org/x/crypto/argon2"
)

func main() {
	js.Global().Set("cairnArgon2id", js.FuncOf(argon2id))
	select {}
}

// argon2id derives a 32-byte key from password and salt (both Uint8Array)
// using the Argon2id parameters t (passes), m (memory in KiB), and p
// (lanes). On invalid arguments it returns a JS Error instead of panicking;
// the loader checks for that and throws it.
func argon2id(this js.Value, args []js.Value) any {
	if len(args) != 5 {
		return jsError("cairnArgon2id: want 5 arguments, got %d", len(args))
	}
	password, err := bytesOf(args[0])
	if err != nil {
		return jsError("cairnArgon2id: password: %v", err)
	}
	salt, err := bytesOf(args[1])
	if err != nil {
		return jsError("cairnArgon2id: salt: %v", err)
	}
	for i, name := range [3]string{"t", "m", "p"} {
		if args[2+i].Type() != js.TypeNumber {
			return jsError("cairnArgon2id: %s must be a number", name)
		}
	}
	t, m, p := args[2].Int(), args[3].Int(), args[4].Int()
	if p < 1 || p > 255 {
		return jsError("cairnArgon2id: p must be between 1 and 255")
	}
	// argon2.IDKey panics on these, and a panic ends the Go program, so
	// every later call would fail too.
	if t < 1 {
		return jsError("cairnArgon2id: t must be at least 1")
	}
	if m < 8*p {
		return jsError("cairnArgon2id: m must be at least 8*p")
	}
	key := argon2.IDKey(password, salt, uint32(t), uint32(m), uint8(p), 32)
	out := js.Global().Get("Uint8Array").New(len(key))
	js.CopyBytesToJS(out, key)
	return out
}

// bytesOf copies a JS Uint8Array into a Go byte slice, or reports that the
// value was not one.
func bytesOf(v js.Value) ([]byte, error) {
	if !v.InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, fmt.Errorf("want a Uint8Array")
	}
	b := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(b, v)
	return b, nil
}

func jsError(format string, args ...any) js.Value {
	return js.Global().Get("Error").New(fmt.Sprintf(format, args...))
}
