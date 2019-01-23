package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// EcdhInfo provides shared secret agreement
type EcdhInfo struct {
	curve   elliptic.Curve
	private []byte
}

// GeneratePubKey generates hex-encoded ECDH public key in uncompressed format
func (e *EcdhInfo) GeneratePubKey() string {
	priv, x, y, err := elliptic.GenerateKey(e.curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	e.private = priv
	pub := elliptic.Marshal(e.curve, x, y)
	return hex.EncodeToString(pub)
}

// GenerateSharedSecret generates SHA256-hashed-then-hex-encoded string with shared secret
// receiving hex-encoded public key from other side of handshaking in uncompressed format
func (e *EcdhInfo) GenerateSharedSecret(sharedHex string) (string, error) {
	sharedKey, err := hex.DecodeString(sharedHex)
	if err != nil {
		return "", err
	}
	x, y := elliptic.Unmarshal(e.curve, sharedKey)
	keyX, _ := e.curve.ScalarMult(x, y, e.private)
	hashKey := sha256.Sum256(keyX.Bytes())
	return fmt.Sprintf("%x", hashKey), nil
}
