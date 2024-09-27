package types

import (
	"crypto/ed25519"
	"math/big"

	"github.com/near/borsh-go"
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


func (pubKey *PublicKey) FromEd25519(edPk ed25519.PublicKey) {
	pubKey.KeyType = ED25519
	copy(pubKey.Data[:], edPk)
}


func (pubKey *PublicKey) ToEd25519() ed25519.PublicKey {
	return ed25519.PublicKey(pubKey.Data[:])
}

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

// A Transaction encodes a NEAR transaction.
type Transaction struct {
	SignerID   string
	PublicKey  PublicKey
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
	PublicKey PublicKey
}

// The AddKey action.
type AddKey struct {
	PublicKey PublicKey
	AccessKey AccessKey
}

// The DeleteKey action.
type DeleteKey struct {
	PublicKey PublicKey
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
