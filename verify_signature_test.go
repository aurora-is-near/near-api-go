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
	message := []byte("+16005551111evm.test-account.testnet")
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
		t.Fatal("Signature should be valid for the given public key")
	}
}

func TestVerifySignaturePrecomputed(t *testing.T) {
	message := "+16005551111evm.test-account.testnet"
	pubKey := "86fd8e75c00c88ad489b3c0c7dd8d13ef0953d4b03788acb05b281b2acd2bf86"
	signature := "a45ea2a6999a69b35a8a9fc3eb60f2440c1d4f7a45641eb81f309a27dbd0342258159d99cd4f322deec8f028214e72072480c9d145b25d5f0f0f3df8f8f9c30b"

	// Convert message to hex
	messageHex := hex.EncodeToString([]byte(message))

	// Verify the signature
	isValid, err := VerifySignatureHex(pubKey, signature, messageHex)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !isValid {
		t.Fatal("Signature should be valid for the given public key")
	}
}

func TestVerifySignatureString(t *testing.T) {
	message := "+16005551111evm.test-account.testnet"
	pubKey := "ed25519:3MVWwQTnSU8RVNe1Z5Ytv9zVE16aXLuHkvEha4LvDH1z"
	signature := "ed25519:3cn6uwA9hVtK8S4ib2coEt8HTV1pjuCLtZs5iUx4zKmXhAUd73rhXcmG2icFk1mF5zy4B2wVkjoisWZQczDG5nXV"

	// Convert message to hex
	messageHex := hex.EncodeToString([]byte(message))

	// Verify the signature
	isValid, err := VerifySignatureBase58(pubKey, signature, messageHex)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !isValid {
		t.Fatal("Signature should be valid for the given public key")
	}
}
