package near

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/aurora-is-near/near-api-go/types"
	"github.com/aurora-is-near/near-api-go/utils"
	"github.com/near/borsh-go"
)

// VerifyTransactionSignature verifies the signature of a given signed transaction.
// It returns true if the signature is valid, false otherwise.
func VerifyTransactionSignature(signedTx *types.SignedTransaction) (bool, error) {
	// Serialize the unsigned transaction
	unsignedTx := signedTx.Transaction
	serializedTx, err := borsh.Serialize(unsignedTx)
	if err != nil {
		return false, err
	}

	// Compute the hash of the serialized transaction
	txHash := sha256.Sum256(serializedTx)

	// Extract the public key from the transaction
	publicKeyData := unsignedTx.PublicKey.Data[:]
	if unsignedTx.PublicKey.KeyType != types.ED25519 {
		return false, errors.New("unsupported key type")
	}

	// Extract the signature from the signed transaction
	signatureData := signedTx.Signature.Data[:]
	if signedTx.Signature.KeyType != types.ED25519 {
		return false, errors.New("unsupported signature key type")
	}

	// Verify the signature
	isValid := ed25519.Verify(publicKeyData, txHash[:], signatureData)
	if !isValid {
		return false, errors.New("invalid signature")
	}

	return true, nil
}

// Verify signature of a given public key and signature
func VerifySignatureBytes(publicKey []byte, signature []byte, message []byte) (bool, error) {
	pubKey := types.PublicKey{}
	pubKey.FromEd25519(publicKey)

	signatureData := signature[:]
	if len(signatureData) != ed25519.SignatureSize {
		return false, errors.New("invalid signature size")
	}

	hash := sha256.Sum256(message)
	return ed25519.Verify(pubKey.ToEd25519(), hash[:], signatureData), nil
}

// Verify signature of a given public key and signature as a hex string
func VerifySignatureHex(publicKeyHex string, signatureHex string, messageHex string) (bool, error) {
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, err
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, err
	}
	message, err := hex.DecodeString(messageHex)
	if err != nil {
		return false, err
	}
	return VerifySignatureBytes(publicKey, signature, message)
}

// VerifySignature verifies a signature given the public key, signature, and message as strings.
// The public key and signature should be in the "ed25519:..." format.
func VerifySignatureBase58(pubKeyStr, signatureStr, messageHex string) (bool, error) {
	// Parse the public key
	pubKey, err := utils.Ed25519PublicKeyFromString(pubKeyStr)
	if err != nil {
		return false, err
	}

	// Parse the signature
	signature, err := utils.Ed25519SignatureFromString(signatureStr)
	if err != nil {
		return false, err
	}

	// Decode the message from hex
	messageBytes, err := hex.DecodeString(messageHex)
	if err != nil {
		return false, err
	}

	// Hash the message
	hash := sha256.Sum256(messageBytes)

	// Verify the signature
	isValid := ed25519.Verify(pubKey, hash[:], signature)

	return isValid, nil
}
