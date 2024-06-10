package utils

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
)

// All supported key types
const (
	ED25519 = 0
)

// PublicKey encoding for NEAR.
type PublicKey struct {
	KeyType uint8
	Data    [32]byte
}

// PublicKeyFromEd25519 derives a public key in NEAR encoding from pk.
func PublicKeyFromEd25519(pk ed25519.PublicKey) PublicKey {
	var pubKey PublicKey
	pubKey.KeyType = ED25519
	copy(pubKey.Data[:], pk)
	return pubKey
}

const ed25519Prefix = "ed25519:"

// Ed25519PublicKeyFromString derives an ed25519 public key from its base58 string representation prefixed with 'ed25519:'.
func Ed25519PublicKeyFromString(ed25519PublicKey string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(ed25519PublicKey, ed25519Prefix) {
		return nil, fmt.Errorf("'%s' is not an Ed25519 key", ed25519PublicKey)
	}
	keyBytes := base58.Decode(strings.TrimPrefix(ed25519PublicKey, ed25519Prefix))
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("unexpected byte length for public key '%s'", ed25519PublicKey)
	}
	return ed25519.PublicKey(keyBytes), nil
}

// Ed25519PrivateKeyFromString derives an ed25519 private key from its base58 string representation prefixed with 'ed25519:'.
func Ed25519PrivateKeyFromString(ed25519PrivateKey string) (ed25519.PrivateKey, error) {
	if !strings.HasPrefix(ed25519PrivateKey, ed25519Prefix) {
		return nil, fmt.Errorf("'%s' is not an Ed25519 key", ed25519PrivateKey)
	}
	keyBytes := base58.Decode(strings.TrimPrefix(ed25519PrivateKey, ed25519Prefix))
	if len(keyBytes) != 64 {
		return nil, fmt.Errorf("unexpected byte length for private key '%s'", ed25519PrivateKey)
	}
	return ed25519.PrivateKey(keyBytes), nil
}

// Ed25519PublicKeyToString converts ed25519 public key to string.
func Ed25519PublicKeyToString(pk ed25519.PublicKey) string {
	return ed25519Prefix + base58.Encode(pk)
}

// Ed25519PrivateKeyToString converts ed25519 private key to string.
func Ed25519PrivateKeyToString(pk ed25519.PrivateKey) string {
	return ed25519Prefix + base58.Encode(pk)
}
