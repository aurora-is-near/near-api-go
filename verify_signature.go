package near

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"github.com/aurora-is-near/near-api-go/types"
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
