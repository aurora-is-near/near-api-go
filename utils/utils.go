// Package utils implements helper functions for the Go NEAR API.
package utils

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
)

// Ed25519SignatureFromString derives an ed25519 signature from its base58 string representation prefixed with 'ed25519:'.
func Ed25519SignatureFromString(ed25519Signature string) ([]byte, error) {
	if !strings.HasPrefix(ed25519Signature, ed25519Prefix) {
		return nil, fmt.Errorf("'%s' is not an Ed25519 signature", ed25519Signature)
	}
	signatureBytes := base58.Decode(strings.TrimPrefix(ed25519Signature, ed25519Prefix))
	if len(signatureBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("unexpected byte length for signature '%s'", ed25519Signature)
	}
	return signatureBytes, nil
}
