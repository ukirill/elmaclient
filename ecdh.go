package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// EcdhInfo provides shared secret agreement
type EcdhInfo struct {
	curve   elliptic.Curve
	private []byte
}

// NewEcdh creates new EcdhInfo struct. If curve is undefined (nil), inits struct with P256
func NewEcdh(curve elliptic.Curve) *EcdhInfo {
	if curve == nil {
		curve = elliptic.P256()
	}
	return &EcdhInfo{curve, nil}
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
func (e *EcdhInfo) GenerateSharedSecret(sharedHex string) ([]byte, error) {
	sharedKey, err := hex.DecodeString(sharedHex)
	if err != nil {
		return nil, err
	}
	x, y := elliptic.Unmarshal(e.curve, sharedKey)
	keyX, _ := e.curve.ScalarMult(x, y, e.private)
	hashKey := sha256.Sum256(keyX.Bytes())
	return hashKey[:], nil
}
