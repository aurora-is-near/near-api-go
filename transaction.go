package near

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"

	"github.com/aurora-is-near/near-api-go/types"
	"github.com/near/borsh-go"
)

func fullAccessKey() types.AccessKey {
	return types.AccessKey{
		Nonce: 0,
		Permission: types.AccessKeyPermission{
			Enum:       1,
			FullAccess: 1,
		},
	}
}

func createTransaction(
	signerID string,
	publicKey ed25519.PublicKey,
	receiverID string,
	nonce uint64,
	blockHash []byte,
	actions []types.Action,
) *types.Transaction {
	var tx types.Transaction
	tx.SignerID = signerID
	tx.PublicKey.FromEd25519(publicKey)
	tx.ReceiverID = receiverID
	tx.Nonce = nonce
	copy(tx.BlockHash[:], blockHash)
	tx.Actions = actions
	return &tx
}

func signTransactionObject(
	tx *types.Transaction,
	privKey ed25519.PrivateKey,
) (txHash []byte, signedTx *types.SignedTransaction, err error) {
	buf, err := borsh.Serialize(*tx)
	if err != nil {
		return nil, nil, err
	}

	hash := sha256.Sum256(buf)

	sig, err := privKey.Sign(rand.Reader, hash[:], crypto.Hash(0))
	if err != nil {
		return nil, nil, err
	}

	var signature types.Signature
	signature.KeyType = types.ED25519
	copy(signature.Data[:], sig)

	var stx types.SignedTransaction
	stx.Transaction = *tx
	stx.Signature = signature

	return hash[:], &stx, nil
}

func signTransaction(
	receiverID string,
	nonce uint64,
	actions []types.Action,
	blockHash []byte,
	publicKey ed25519.PublicKey,
	privKey ed25519.PrivateKey,
	accountID string,
) (txHash []byte, signedTx *types.SignedTransaction, err error) {
	// create transaction
	tx := createTransaction(accountID, publicKey,
		receiverID, nonce, blockHash, actions)

	// sign transaction object
	txHash, signedTx, err = signTransactionObject(tx, privKey)
	if err != nil {
		return nil, nil, err
	}
	return txHash, signedTx, nil
}
