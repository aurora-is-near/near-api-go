package near

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/aurora-is-near/near-api-go/keystore"
	"github.com/aurora-is-near/near-api-go/utils"
	"github.com/btcsuite/btcutil/base58"
	"github.com/near/borsh-go"
	"math/big"
	"path/filepath"
	"strconv"
	"sync"
)

// Default number of retries with different nonce before giving up on a transaction.
const txNonceRetryNumber = 12

// Default wait until next retry in milliseconds.
const txNonceRetryWait = 500

// Exponential back off for waiting to retry.
const txNonceRetryWaitBackoff = 1.5

// Account defines access credentials for a NEAR account.
type Account struct {

	// NEAR JSON-RPC connection
	conn *Connection

	// keeps full access key for account and operations
	fullAccessKeyPair *keystore.Ed25519KeyPair

	// consists of function call key pairs if they exist, otherwise contains only full access key
	// (i.e.: contains one key which points to same fullAccessKeyPair)
	funcCallKeyPairs map[string]*keystore.Ed25519KeyPair

	// to atomically get Near Nonce per key
	funcCallKeyMutexes map[string]*sync.Mutex

	accessKeyByPublicKeyCache map[string]map[string]interface{}
}

// LoadAccount loads the credential for the receiverID account, to be used via
// connection c, and returns it.
func LoadAccount(c *Connection, cfg *Config, receiverID string) (*Account, error) {
	var (
		a       Account
		err     error
		keyPair *keystore.Ed25519KeyPair
	)
	a.conn = c
	a.funcCallKeyPairs = make(map[string]*keystore.Ed25519KeyPair)
	a.funcCallKeyMutexes = make(map[string]*sync.Mutex)
	a.accessKeyByPublicKeyCache = make(map[string]map[string]interface{})

	path := cfg.KeyPath
	if path == "" {
		// set default path if not defined in config
		path = filepath.Join(home, ".near-credentials", cfg.NetworkID, receiverID+".json")
	}

	// set full access key first
	a.fullAccessKeyPair, err = keystore.LoadKeyPairFromPath(path, receiverID)
	if err != nil {
		return nil, err
	}

	// set function call keys if any
	keyPairFilePaths := getFunctionCallKeyPairFilePaths(path, cfg.FunctionKeyPrefixPattern)
	for _, p := range keyPairFilePaths {
		keyPair, err = keystore.LoadKeyPairFromPath(p, receiverID)
		if err != nil {
			return nil, err
		}
		a.funcCallKeyPairs[keyPair.PublicKey] = keyPair
		a.funcCallKeyMutexes[keyPair.PublicKey] = &sync.Mutex{}
	}

	return &a, nil
}

// GetVerifiedAccessKeys verifies and returns the public keys of the access keys
func (a *Account) GetVerifiedAccessKeys() []string {
	accessKeys := make([]string, 0)
	for k, v := range a.funcCallKeyPairs {
		_, err := a.conn.ViewAccessKey(v.AccountID, k)
		if err != nil {
			continue
		}
		accessKeys = append(accessKeys, k)
	}
	return accessKeys
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
	return a.SignAndSendTransaction(a.fullAccessKeyPair.AccountID, []Action{
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
	buf, err := utils.ExponentialBackoff(txNonceRetryWait, txNonceRetryNumber, txNonceRetryWaitBackoff,
		func() ([]byte, error) {
			_, signedTx, err := a.signTransaction(receiverID, actions)
			if err != nil {
				return nil, err
			}

			buf, err := borsh.Serialize(*signedTx)
			if err != nil {
				return nil, err
			}
			return buf, nil

		})
	if err != nil {
		return nil, err
	}
	return a.conn.SendTransaction(buf)
}

// SignAndSendTransactionWithKey signs the given actions and sends them as a transaction to receiverID.
func (a *Account) SignAndSendTransactionWithKey(
	receiverID string,
	publicKey string,
	actions []Action,
) (map[string]interface{}, error) {
	buf, err := utils.ExponentialBackoff(txNonceRetryWait, txNonceRetryNumber, txNonceRetryWaitBackoff,
		func() ([]byte, error) {
			_, signedTx, err := a.signTransactionWithKey(receiverID, publicKey, actions)
			if err != nil {
				return nil, err
			}

			buf, err := borsh.Serialize(*signedTx)
			if err != nil {
				return nil, err
			}
			return buf, nil

		})
	if err != nil {
		return nil, err
	}
	return a.conn.SendTransaction(buf)
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

// SignAndSendTransactionAsyncWithKey signs the given actions and sends it immediately
func (a *Account) SignAndSendTransactionAsyncWithKey(
	receiverID string,
	publicKey string,
	actions []Action,
) (string, error) {
	_, signedTx, err := a.signTransactionWithKey(receiverID, publicKey, actions)
	if err != nil {
		return "", err
	}

	buf, err := borsh.Serialize(*signedTx)
	if err != nil {
		return "", err
	}
	return a.conn.SendTransactionAsync(buf)
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

	// sign transaction
	return signTransaction(receiverID, uint64(nonce), actions, base58.Decode(blockHash),
		a.fullAccessKeyPair.Ed25519PubKey, a.fullAccessKeyPair.Ed25519PrivKey, a.fullAccessKeyPair.AccountID)

}

func (a *Account) signTransactionWithKey(
	receiverID string,
	publicKey string,
	actions []Action,
) ([]byte, *SignedTransaction, error) {

	ak, err := a.findAccessKeyWithPublicKey(publicKey)
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

	// sign transaction
	return signTransaction(receiverID, uint64(nonce), actions, base58.Decode(blockHash),
		a.funcCallKeyPairs[publicKey].Ed25519PubKey, a.funcCallKeyPairs[publicKey].Ed25519PrivKey, a.funcCallKeyPairs[publicKey].AccountID)

}

func (a *Account) findAccessKey() (publicKey ed25519.PublicKey, accessKey map[string]interface{}, err error) {
	// TODO: Find matching access key based on transaction
	// TODO: use accountId and networkId?
	pk := a.fullAccessKeyPair.Ed25519PubKey
	if ak := a.accessKeyByPublicKeyCache[string(publicKey)]; ak != nil {
		return pk, ak, nil
	}
	ak, err := a.conn.ViewAccessKey(a.fullAccessKeyPair.AccountID, a.fullAccessKeyPair.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	a.accessKeyByPublicKeyCache[string(publicKey)] = ak
	return pk, ak, nil
}

func (a *Account) findAccessKeyWithPublicKey(publicKey string) (map[string]interface{}, error) {

	a.funcCallKeyMutexes[publicKey].Lock()
	defer a.funcCallKeyMutexes[publicKey].Unlock()
	if ak := a.accessKeyByPublicKeyCache[publicKey]; ak != nil {
		return ak, nil
	}
	ak, err := a.conn.ViewAccessKey(a.funcCallKeyPairs[publicKey].AccountID, publicKey)
	if err != nil {
		return nil, err
	}
	a.accessKeyByPublicKeyCache[publicKey] = ak
	return ak, nil
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

// FunctionCallWithMultiActionAndKey performs a NEAR function call for multiple actions with specific access key.
func (a *Account) FunctionCallWithMultiActionAndKey(
	contractID string,
	methodName string,
	publicKey string,
	argsSlice [][]byte,
	gas uint64,
	amount big.Int,
) (map[string]interface{}, error) {

	actions := make([]Action, 0)
	for _, args := range argsSlice {
		actions = append(actions, Action{
			Enum: 2,
			FunctionCall: FunctionCall{
				MethodName: methodName,
				Args:       args,
				Gas:        gas,
				Deposit:    amount,
			},
		})
	}
	return a.SignAndSendTransactionWithKey(contractID, publicKey, actions)
}

// FunctionCallAsync performs an async NEAR function call.
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

// FunctionCallAsyncWithMultiActionAndKey performs an async NEAR function call.
func (a *Account) FunctionCallAsyncWithMultiActionAndKey(
	contractID string,
	methodName string,
	publicKey string,
	argsSlice [][]byte,
	gas uint64,
	amount big.Int,
) (string, error) {
	actions := make([]Action, 0)
	for _, args := range argsSlice {
		actions = append(actions, Action{
			Enum: 2,
			FunctionCall: FunctionCall{
				MethodName: methodName,
				Args:       args,
				Gas:        gas,
				Deposit:    amount,
			},
		})
	}

	return a.SignAndSendTransactionAsyncWithKey(contractID, publicKey, actions)
}

// ViewFunction calls the provided contract method as a readonly function
func (a *Account) ViewFunction(accountId, methodName string, argsBuf []byte, options *int64) (interface{}, error) {
	finality := "final"
	var blockId int64
	if options != nil {
		switch *options {
		case 0: // "earliest"
			blockId = 1
		case -1: // "latest"
			finality = "final"
		case -2: // "pending"
			finality = "optimistic"
		case -3: // "finalized"
			finality = "final"
		case -4: // "safe":
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

	res, err := a.conn.call("query", rpcQueryMap)
	if err != nil {
		return nil, err
	}
	r, ok := res.(map[string]interface{})
	if !ok {
		return nil, ErrNotObject
	}
	return r, nil
}

// getFunctionCallKeyPairFilePaths takes a path of full access key file and returns a list of access key(s) according the below rules;
// Given the path to full access key /home/user/.near-credentials/mainnet/user.near.json
//   - if there are files matching the pattern /home/user/.near-credentials/mainnet/fk*.user.near.json, it only returns the file paths to function call keys
//   - if there is only /home/user/.near-credentials/mainnet/user.near.json, it returns the full access key defined in `path` arg
//   - if there is any error, it returns the full access key defined in `path` arg
func getFunctionCallKeyPairFilePaths(path, prefixPattern string) []string {
	dir, file := filepath.Split(path)
	pattern := filepath.Join(dir, prefixPattern+file)

	keyPairFiles := make([]string, 0)
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		keyPairFiles = append(keyPairFiles, path)
	} else {
		keyPairFiles = append(keyPairFiles, files...)
	}
	return keyPairFiles
}
