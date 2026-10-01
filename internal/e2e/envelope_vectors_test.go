package e2e

import (
	"bytes"
	"strings"
	"testing"
)

// envelopeVec is a raw envelope wrapper JSON text that Envelope.UnmarshalJSON
// and decodeEnvelope must both accept or both refuse. An accepted entry must
// also re-encode (MarshalJSON / JSON.stringify of the decoded object) to
// exactly JSON, so an acceptance that silently dropped or rewrote a field
// fails too.
type envelopeVec struct {
	Name   string `json:"name"`
	JSON   string `json:"json"`
	Accept bool   `json:"accept"`
	Why    string `json:"why"`
}

// envelopeVectors builds the envelope section. Each refusal differs from an
// accepted envelope in the one way its Why names.
func envelopeVectors() []envelopeVec {
	body := B64([]byte(`{"v":1}`))
	sig := B64(fillBytes(64))
	newSig := B64(bytes.Repeat([]byte{0x5a}, 64))
	mid := len(sig) / 2
	env := func(fields ...string) string { return "{" + strings.Join(fields, ",") + "}" }
	str := func(k, v string) string { return `"` + k + `":"` + v + `"` }
	b, s, u := str("body", body), str("sig", sig), str("signer", "u1")
	return []envelopeVec{
		{Name: "valid", Accept: true, Why: "body, sig and signer", JSON: env(b, s, u)},
		{Name: "valid-newSig", Accept: true, Why: "a rotation envelope with newSig", JSON: env(b, s, u, str("newSig", newSig))},

		{Name: "duplicate-key", Why: "body appears twice", JSON: env(b, b, s, u)},
		{Name: "trailing-data", Why: "a second JSON value after the envelope", JSON: env(b, s, u) + " {}"},
		{Name: "case-variant-key", Why: `"Signer" instead of "signer"`, JSON: env(b, s, str("Signer", "u1"))},
		{Name: "unknown-key", Why: "a field the envelope does not declare", JSON: env(b, s, u, `"extra":1`)},
		{Name: "missing-signer", Why: "signer is absent", JSON: env(b, s)},
		{Name: "non-string-signer", Why: "signer is a number", JSON: env(b, s, `"signer":1`)},
		{Name: "null-body", Why: "body is null", JSON: env(`"body":null`, s, u)},
		{Name: "newSig-empty", Why: `"newSig":"" is not the same as an absent newSig`, JSON: env(b, s, u, str("newSig", ""))},
		{Name: "newSig-null", Why: "newSig is null", JSON: env(b, s, u, `"newSig":null`)},
		{Name: "body-base64-lf", Why: "body has an embedded line feed", JSON: env(str("body", body[:4]+`\n`+body[4:]), s, u)},
		{Name: "body-base64-padded", Why: "body is padded with equals", JSON: env(str("body", body+"="), s, u)},
		{Name: "sig-base64-cr", Why: "sig has a trailing carriage return", JSON: env(b, str("sig", sig+`\r`), u)},
		{Name: "sig-base64-plus", Why: "sig uses the standard alphabet's plus sign", JSON: env(b, str("sig", "+"+sig[1:]), u)},
		{Name: "newSig-base64-crlf", Why: "newSig has an embedded CR LF", JSON: env(b, s, u, str("newSig", newSig[:mid]+`\r\n`+newSig[mid:]))},
		{Name: "newSig-base64-slash", Why: "newSig uses the standard alphabet's slash", JSON: env(b, s, u, str("newSig", "/"+newSig[1:]))},
		{Name: "lone-surrogate-escape", Why: "signer holds an unpaired surrogate escape", JSON: env(b, s, str("signer", `u\ud800`))},
	}
}

// checkEnvelopeVectors runs every envelope entry through
// Envelope.UnmarshalJSON directly (json.Unmarshal would refuse some inputs
// itself before the strict decoder ever saw them).
func checkEnvelopeVectors(t *testing.T, vs []envelopeVec) {
	t.Helper()
	for _, v := range vs {
		var e Envelope
		err := e.UnmarshalJSON([]byte(v.JSON))
		if !v.Accept {
			if err == nil {
				t.Errorf("%s (%s): UnmarshalJSON accepted it", v.Name, v.Why)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: UnmarshalJSON: %v", v.Name, err)
			continue
		}
		again, err := e.MarshalJSON()
		if err != nil || string(again) != v.JSON {
			t.Errorf("%s: re-encodes to %s, want %s (%v)", v.Name, again, v.JSON, err)
		}
	}
}
