package near

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	// Generate a new key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create a message to sign
	message := []byte("test message")
	messageHex := hex.EncodeToString(message)

	// Hash the message
	hash := sha256.Sum256(message)

	// Sign the hashed message
	signature := ed25519.Sign(privKey, hash[:])
	signatureHex := hex.EncodeToString(signature)

	// Verify the signature
	isValid, err := VerifySignatureBytes(pubKey, signature, message)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !isValid {
		t.Fatal("Signature is not valid")
	}

	// Test invariant: Verify that the signature is invalid for a different message
	otherMessage := []byte("different message")
	isValid, err = VerifySignatureBytes(pubKey, signature, otherMessage)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if isValid {
		t.Fatal("Signature should not be valid for a different message")
	}

	// Test invariant: Verify that the signature is invalid for a different public key
	otherPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	isValid, err = VerifySignatureBytes(otherPubKey, signature, message)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if isValid {
		t.Fatal("Signature should not be valid for a different public key")
	}

	// Test VerifySignatureHex
	isValid, err = VerifySignatureHex(hex.EncodeToString(pubKey), signatureHex, messageHex)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !isValid {
		t.Fatal("Signature should be valid for a different public key")
	}
}
