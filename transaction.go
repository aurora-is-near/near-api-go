package near

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/aurora-is-near/near-api-go/utils"
	"github.com/near/borsh-go"
)

// AccessKey encodes a NEAR access key.
type AccessKey struct {
	Nonce      uint64
	Permission AccessKeyPermission
}

// AccessKeyPermission encodes a NEAR access key permission.
type AccessKeyPermission struct {
	Enum         borsh.Enum `borsh_enum:"true"` // treat struct as complex enum when serializing/deserializing
	FunctionCall FunctionCallPermission
	FullAccess   borsh.Enum
}

// FunctionCallPermission encodes a NEAR function call permission (an access
// key permission).
type FunctionCallPermission struct {
	Allowance   *big.Int
	ReceiverId  string
	MethodNames []string
}

func fullAccessKey() AccessKey {
	return AccessKey{
		Nonce: 0,
		Permission: AccessKeyPermission{
			Enum:       1,
			FullAccess: 1,
		},
	}
}

// A Transaction encodes a NEAR transaction.
type Transaction struct {
	SignerID   string
	PublicKey  utils.PublicKey
	Nonce      uint64
	ReceiverID string
	BlockHash  [32]byte
	Actions    []Action
}

// Action simulates an enum for Borsh encoding.
type Action struct {
	Enum           borsh.Enum `borsh_enum:"true"` // treat struct as complex enum when serializing/deserializing
	CreateAccount  borsh.Enum
	DeployContract DeployContract
	FunctionCall   FunctionCall
	Transfer       Transfer
	Stake          Stake
	AddKey         AddKey
	DeleteKey      DeleteKey
	DeleteAccount  DeleteAccount
}

// The DeployContract action.
type DeployContract struct {
	Code []byte
}

// The FunctionCall action.
type FunctionCall struct {
	MethodName string
	Args       []byte
	Gas        uint64
	Deposit    big.Int // u128
}

// The Transfer action.
type Transfer struct {
	Deposit big.Int // u128
}

// The Stake action.
type Stake struct {
	Stake     big.Int // u128
	PublicKey utils.PublicKey
}

// The AddKey action.
type AddKey struct {
	PublicKey utils.PublicKey
	AccessKey AccessKey
}

// The DeleteKey action.
type DeleteKey struct {
	PublicKey utils.PublicKey
}

// The DeleteAccount action.
type DeleteAccount struct {
	BeneficiaryID string
}

// A Signature used for signing transaction.
type Signature struct {
	KeyType uint8
	Data    [64]byte
}

// SignedTransaction encodes signed transactions for NEAR.
type SignedTransaction struct {
	Transaction Transaction
	Signature   Signature
}

func createTransaction(
	signerID string,
	publicKey utils.PublicKey,
	receiverID string,
	nonce uint64,
	blockHash []byte,
	actions []Action,
) *Transaction {
	var tx Transaction
	tx.SignerID = signerID
	tx.PublicKey = publicKey
	tx.ReceiverID = receiverID
	tx.Nonce = nonce
	copy(tx.BlockHash[:], blockHash)
	tx.Actions = actions
	return &tx
}

func GetTransactionBytesMsg(tx *Transaction) (*[32]byte, error) {
	buf, err := borsh.Serialize(*tx)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(buf)
	return &hash, nil
}

func signTransactionObject(
	tx *Transaction,
	privKey ed25519.PrivateKey,
	accountID string,
) (txHash []byte, signedTx *SignedTransaction, err error) {

	hash, err := GetTransactionBytesMsg(tx)
	if err != nil {
		return nil, nil, err
	}

	sig, err := privKey.Sign(rand.Reader, hash[:], crypto.Hash(0))
	if err != nil {
		return nil, nil, err
	}

	var signature Signature
	signature.KeyType = utils.ED25519
	copy(signature.Data[:], sig)

	var stx SignedTransaction
	stx.Transaction = *tx
	stx.Signature = signature

	return hash[:], &stx, nil
}

func signTransaction(
	receiverID string,
	nonce uint64,
	actions []Action,
	blockHash []byte,
	publicKey ed25519.PublicKey,
	privKey ed25519.PrivateKey,
	accountID string,
) (txHash []byte, signedTx *SignedTransaction, err error) {
	// create transaction
	tx := createTransaction(accountID, utils.PublicKeyFromEd25519(publicKey),
		receiverID, nonce, blockHash, actions)

	// sign transaction object
	txHash, signedTx, err = signTransactionObject(tx, privKey, accountID)
	if err != nil {
		return nil, nil, err
	}
	return txHash, signedTx, nil
}
