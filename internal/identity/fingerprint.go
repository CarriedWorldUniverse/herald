package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
)

// fingerprintBytes is how many bytes of the SHA-256 digest go into a
// fingerprint. 16 bytes (128 bits) base64url-encoded is short enough to log
// and index, with negligible collision risk for an identity directory.
const fingerprintBytes = 16

// Fingerprint is herald's stable identifier for a casket Ed25519 public key:
// base64url(sha256(pubkey)[:16]). Deterministic — the same key always yields
// the same fingerprint. casket-go has no fingerprint convention of its own
// (WIRE.md covers channel framing, not key fingerprints), so herald defines
// this; if casket adopts one later, align here.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:fingerprintBytes])
}
