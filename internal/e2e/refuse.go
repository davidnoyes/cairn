package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// refuseBlobLen is the length of a sealed 32-byte key.
const refuseBlobLen = 61

// RefuseFake is what refuse/begin returns for an address with no pending
// request, so the response looks like a real one and stays stable across
// calls. Every value is derived from the server secret and the normalized
// address under LabelRefuseFake. id is shaped like a user ID, a version 4
// UUID, and each blob like a sealed 32-byte key: 61 bytes that start with
// the version byte 0x01.
func RefuseFake(serverSecret []byte, email string) (id string, mkRecovery, ed25519Priv []byte) {
	email = NormalizeEmail(email)
	var stream []byte
	for i := byte(0); len(stream) < 16+2*refuseBlobLen; i++ {
		mac := hmac.New(sha256.New, serverSecret)
		mac.Write(Enc([]byte(LabelRefuseFake), []byte(email), []byte{i}))
		stream = mac.Sum(stream)
	}
	u := stream[:16]
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	id = fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	mkRecovery = append([]byte(nil), stream[16:16+refuseBlobLen]...)
	ed25519Priv = append([]byte(nil), stream[16+refuseBlobLen:16+2*refuseBlobLen]...)
	mkRecovery[0], ed25519Priv[0] = sealVersion, sealVersion
	return id, mkRecovery, ed25519Priv
}

// RefuseFakeRequestedAt is the requestedAt refuse/begin returns with the fake:
// a whole second in the wait before now, as a pending request's is. It holds
// for one wait and then moves on by exactly the wait, as a real request gives
// way to the fake at its release. The offset within the wait is derived from
// the server secret and the normalized address under LabelRefuseFake.
func RefuseFakeRequestedAt(serverSecret []byte, email string, now time.Time, wait time.Duration) time.Time {
	mac := hmac.New(sha256.New, serverSecret)
	mac.Write(Enc([]byte(LabelRefuseFake), []byte(NormalizeEmail(email)), []byte("requestedAt")))
	period := int64(wait / time.Second)
	offset := int64(binary.BigEndian.Uint64(mac.Sum(nil)) % uint64(period))
	since := now.Unix() - offset
	start := since - since%period
	if since%period < 0 {
		start -= period
	}
	return time.Unix(start+offset, 0).UTC()
}
