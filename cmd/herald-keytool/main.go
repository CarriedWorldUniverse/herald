// Command herald-keytool is a small CLI for casket agent keys + herald
// jwt-bearer assertions. It is the seed of the agent-runtime client (NEX-383):
// derive an agent's casket keypair, and sign the assertion an agent presents to
// herald's /token endpoint.
//
//	herald-keytool derive <owner-seed> <agent-slug>
//	    -> prints "<pubB64Std> <privB64Std>"  (ed25519)
//
//	herald-keytool assert <privB64Std> <agent-id> <token-endpoint-url>
//	    -> prints a compact EdDSA-signed jwt-bearer assertion
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	casket "github.com/CarriedWorldUniverse/casket-go"
	jose "github.com/go-jose/go-jose/v4"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: herald-keytool derive|assert ...")
	}
	switch os.Args[1] {
	case "derive":
		if len(os.Args) != 4 {
			fail("usage: herald-keytool derive <owner-seed> <agent-slug>")
		}
		priv, pub, err := casket.DeriveAgentKey([]byte(os.Args[2]), os.Args[3])
		if err != nil {
			fail("derive: %v", err)
		}
		fmt.Printf("%s %s\n",
			base64.StdEncoding.EncodeToString(pub),
			base64.StdEncoding.EncodeToString(priv))
	case "assert":
		if len(os.Args) != 5 {
			fail("usage: herald-keytool assert <privB64> <agent-id> <token-url>")
		}
		raw, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil {
			fail("assert: bad priv b64: %v", err)
		}
		priv := ed25519.PrivateKey(raw)
		agentID, tokenURL := os.Args[3], os.Args[4]
		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
			(&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			fail("assert: signer: %v", err)
		}
		payload, _ := json.Marshal(map[string]any{
			"iss": agentID, "sub": agentID, "aud": tokenURL,
			"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(),
		})
		obj, err := signer.Sign(payload)
		if err != nil {
			fail("assert: sign: %v", err)
		}
		s, _ := obj.CompactSerialize()
		fmt.Println(s)
	default:
		fail("unknown command %q", os.Args[1])
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
