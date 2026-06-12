package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func TestCodeStoreIssueRedeem(t *testing.T) {
	now := time.Now()
	cs := NewCodeStore(func() time.Time { return now })
	code := cs.Issue(PendingAuth{ClientID: "atlas", RedirectURI: "https://a/cb", UserID: "u1", CodeChallenge: "ch"})
	if code == "" {
		t.Fatal("empty code")
	}
	pa, ok := cs.Redeem(code)
	if !ok || pa.UserID != "u1" || pa.ClientID != "atlas" {
		t.Fatalf("redeem: %+v ok=%v", pa, ok)
	}
	if _, ok := cs.Redeem(code); ok {
		t.Fatal("code must be single-use")
	}
}

func TestCodeStoreExpiry(t *testing.T) {
	now := time.Now()
	cs := NewCodeStore(func() time.Time { return now })
	code := cs.Issue(PendingAuth{UserID: "u1"})
	now = now.Add(61 * time.Second)
	if _, ok := cs.Redeem(code); ok {
		t.Fatal("expired code must not redeem")
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !VerifyPKCE(challenge, verifier) {
		t.Fatal("valid S256 verifier rejected")
	}
	if VerifyPKCE(challenge, "wrong-verifier") {
		t.Fatal("wrong verifier accepted")
	}
	if VerifyPKCE("", "anything") {
		t.Fatal("empty challenge must never verify")
	}
}
