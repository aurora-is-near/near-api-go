package near

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strconv"

	"github.com/aurora-is-near/near-api-go/keystore"
	"github.com/aurora-is-near/near-api-go/utils"
	"github.com/btcsuite/btcutil/base58"
	"github.com/near/borsh-go"
)

const ed25519Prefix = "ed25519:"

// Default number of retries with different nonce before giving up on a transaction.
const TxNonceRetryNumber = 12

// Default wait until next retry in milli seconds.
const TxNonceRetryWait = 500

// Exponential back off for waiting to retry.
const TxNonceRetryWaitBackoff = 1.5

// Account defines access credentials for a NEAR account.
type Account struct {
	conn                      *Connection
	kp                        *keystore.Ed25519KeyPair
	accessKeyByPublicKeyCache map[string]map[string]interface{}
}

func LoadAccountDirectly(c *Connection, kp *keystore.Ed25519KeyPair, accessKeyByPublicKeyCache map[string]map[string]interface{}) *Account {
	return &Account{
		conn:                      c,
		kp:                        kp,
		accessKeyByPublicKeyCache: accessKeyByPublicKeyCache,
	}
}

// LoadAccount loads the credential for the receiverID account, to be used via
// connection c, and returns it.
func LoadAccount(c *Connection, cfg *Config, receiverID string) (*Account, error) {
	var (
		a   Account
		err error
	)
	a.conn = c
	if cfg.KeyPath != "" {
		a.kp, err = keystore.LoadKeyPairFromPath(cfg.KeyPath, receiverID)
	} else {
		a.kp, err = keystore.LoadKeyPair(cfg.NetworkID, receiverID)
	}
	if err != nil {
		return nil, err
	}
	a.accessKeyByPublicKeyCache = make(map[string]map[string]interface{})
	return &a, nil
}

// SendMoney sends amount NEAR from account to receiverID.
func (a *Account) SendMoney(
	receiverID string,
	amount big.Int,
) (map[string]interface{}, error) {
	return a.SignAndSendTransaction(receiverID, []Action{
		{
			Enum: 3,
			Transfer: Transfer{
				Deposit: amount,
			},
		},
	})
}

// CreateAccount creates the newAccountID with the given publicKey and amount.
func (a *Account) CreateAccount(
	newAccountID string,
	publicKey utils.PublicKey,
	amount big.Int,
) (map[string]interface{}, error) {
	return a.SignAndSendTransaction(newAccountID, []Action{
		{
			Enum:          0,
			CreateAccount: 0,
		},
		{
			Enum: 3,
			Transfer: Transfer{
				Deposit: amount,
			},
		},
		{
			Enum: 5,
			AddKey: AddKey{
				PublicKey: publicKey,
				AccessKey: fullAccessKey(),
			},
		},
	})
}

// DeleteAccount deletes the account and sends the remaining Ⓝ balance to the
// account beneficiaryID.
func (a *Account) DeleteAccount(
	beneficiaryID string,
) (map[string]interface{}, error) {
	return a.SignAndSendTransaction(a.kp.AccountID, []Action{
		{
			Enum: 7,
			DeleteAccount: DeleteAccount{
				BeneficiaryID: beneficiaryID,
			},
		},
	})
}

// SignAndSendTransaction signs the given actions and sends them as a transaction to receiverID.
func (a *Account) SignAndSendTransaction(
	receiverID string,
	actions []Action,
) (map[string]interface{}, error) {
	return utils.ExponentialBackoff(TxNonceRetryWait, TxNonceRetryNumber, TxNonceRetryWaitBackoff,
		func() (map[string]interface{}, error) {
			_, signedTx, err := a.signTransaction(receiverID, actions)
			if err != nil {
				return nil, err
			}

			buf, err := borsh.Serialize(*signedTx)
			if err != nil {
				return nil, err
			}

			return a.conn.SendTransaction(buf)
		})
}

// SignAndSendTransactionAsync signs the given actions and sends it immediately
func (a *Account) SignAndSendTransactionAsync(
	receiverID string,
	actions []Action,
) (string, error) {
	_, signedTx, err := a.signTransaction(receiverID, actions)
	if err != nil {
		return "", err
	}

	buf, err := borsh.Serialize(*signedTx)
	if err != nil {
		return "", err
	}
	return a.conn.SendTransactionAsync(buf)
}

// 构建Transaction信息
func (a *Account) BuildTransaction(receiverID string, actions []Action) (*Transaction, error) {
	_, ak, err := a.findAccessKey()
	if err != nil {
		return nil, err
	}

	// get current block hash
	block, err := a.conn.Block()
	if err != nil {
		return nil, err
	}
	blockHash := block["header"].(map[string]interface{})["hash"].(string)

	// create next nonce
	var nonce int64
	jsonNonce, ok := ak["nonce"].(json.Number)
	if ok {
		nonce, err = jsonNonce.Int64()
		if err != nil {
			return nil, err
		}
		nonce++
	}

	// save nonce
	ak["nonce"] = json.Number(strconv.FormatInt(nonce, 10))

	decodeblockHash := base58.Decode(blockHash)

	uint64nonce := uint64(nonce)

	tx := createTransaction(a.kp.AccountID, utils.PublicKeyFromEd25519(a.kp.Ed25519PubKey),
		receiverID, uint64nonce, decodeblockHash, actions)

	return tx, nil

}

func (a *Account) signTransaction(
	receiverID string,
	actions []Action,
) (txHash []byte, signedTx *SignedTransaction, err error) {
	_, ak, err := a.findAccessKey()
	if err != nil {
		return nil, nil, err
	}

	// get current block hash
	block, err := a.conn.Block()
	if err != nil {
		return nil, nil, err
	}
	blockHash := block["header"].(map[string]interface{})["hash"].(string)

	// create next nonce
	var nonce int64
	jsonNonce, ok := ak["nonce"].(json.Number)
	if ok {
		nonce, err = jsonNonce.Int64()
		if err != nil {
			return nil, nil, err
		}
		nonce++
	}

	// save nonce
	ak["nonce"] = json.Number(strconv.FormatInt(nonce, 10))

	decodeblockHash := base58.Decode(blockHash)

	uint64nonce := uint64(nonce)
	// sign transaction
	return signTransaction(receiverID, uint64nonce, actions, decodeblockHash,
		a.kp.Ed25519PubKey, a.kp.Ed25519PrivKey, a.kp.AccountID)

}

func (a *Account) findAccessKey() (publicKey ed25519.PublicKey, accessKey map[string]interface{}, err error) {
	// TODO: Find matching access key based on transaction
	// TODO: use accountId and networkId?
	pk := a.kp.Ed25519PubKey
	if ak := a.accessKeyByPublicKeyCache[string(publicKey)]; ak != nil {
		return pk, ak, nil
	}
	ak, err := a.conn.ViewAccessKey(a.kp.AccountID, a.kp.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	a.accessKeyByPublicKeyCache[string(publicKey)] = ak
	return pk, ak, nil
}

// FunctionCall performs a NEAR function call.
func (a *Account) FunctionCall(
	contractID, methodName string,
	args []byte,
	gas uint64,
	amount big.Int,
) (map[string]interface{}, error) {
	return a.SignAndSendTransaction(contractID, []Action{{
		Enum: 2,
		FunctionCall: FunctionCall{
			MethodName: methodName,
			Args:       args,
			Gas:        gas,
			Deposit:    amount,
		},
	}})
}

// FunctionCallAsync performs an asynch NEAR function call.
func (a *Account) FunctionCallAsync(
	contractID, methodName string,
	args []byte,
	gas uint64,
	amount big.Int,
) (string, error) {
	return a.SignAndSendTransactionAsync(contractID, []Action{{
		Enum: 2,
		FunctionCall: FunctionCall{
			MethodName: methodName,
			Args:       args,
			Gas:        gas,
			Deposit:    amount,
		},
	}})
}

// ViewFunction calls the provided contract method as a readonly function
func (a *Account) ViewFunction(accountId, methodName string, argsBuf []byte, options *int64) (interface{}, error) {
	finality := "final"
	var blockId int64
	if options != nil {
		switch *options {
		case 0: //"earliest"
			blockId = 1
		case -1: //"latest"
			finality = "final"
		case -2: //"pending"
			finality = "optimistic"
		case -3: //"finalized"
			finality = "final"
		case -4: //"safe":
			finality = "final"
		default:
			blockId = *options
		}
	}
	rpcQueryMap := map[string]interface{}{
		"request_type": "call_function",
		"account_id":   accountId,
		"method_name":  methodName,
		"args_base64":  base64.StdEncoding.EncodeToString(argsBuf),
	}
	if blockId > 0 {
		rpcQueryMap["block_id"] = blockId
	} else {
		rpcQueryMap["finality"] = finality
	}

	res, err := a.conn.Call("query", rpcQueryMap)
	if err != nil {
		return nil, err
	}
	r, ok := res.(map[string]interface{})
	if !ok {
		return nil, ErrNotObject
	}
	return r, nil
}
