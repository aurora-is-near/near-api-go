// Package near allows to interact with the NEAR platform via RPC calls.
package near

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aurora-is-near/go-jsonrpc"
)

// Connection allows to do JSON-RPC to a NEAR endpoint.
type Connection struct {
	c jsonrpc.RPCClient
}

// NewConnection returns a new connection for JSON-RPC calls to the NEAR
// endpoint with the given nodeURL.
func NewConnection(nodeURL string) *Connection {
	return NewConnectionWithTimeout(nodeURL, 0)
}

// NewConnectionWithTimeout returns a new connection for JSON-RPC calls to the NEAR
// endpoint with the given nodeURL with the given timeout.
func NewConnectionWithTimeout(nodeURL string, timeout time.Duration) *Connection {
	var c Connection
	c.c = jsonrpc.NewClientWithOpts(nodeURL, &jsonrpc.RPCClientOpts{
		HTTPClient: &http.Client{
			Timeout: timeout,
		},
	})
	return &c
}

// call uses the connection c to call the given method with params.
// It handles all possible error cases and returns the result (which cannot be nil).
func (c *Connection) call(method string, params ...interface{}) (interface{}, error) {
	start := time.Now()
	res, err := c.c.Call(method, params...)
	if err != nil {
		return nil, err
	}
	if res.Error != nil {
		if res.Error.Data != nil {
			return nil, fmt.Errorf("near: jsonrpc: %d: %s: %v (after %s)",
				res.Error.Code, res.Error.Message, res.Error.Data, time.Since(start))
		}
		return nil, fmt.Errorf("near: jsonrpc: %d: %s (after %s)",
			res.Error.Code, res.Error.Message, time.Since(start))
	}
	if res.Result == nil {
		return nil, fmt.Errorf("near: JSON-RPC result is nil (after %s)", time.Since(start))
	}
	return res.Result, nil
}

// Block queries network and returns latest block.
//
// For details see https://docs.near.org/docs/interaction/rpc#block
func (c *Connection) Block() (map[string]interface{}, error) {
	res, err := c.call("block", map[string]string{
		"finality": "final",
	})
	if err != nil {
		return nil, err
	}
	r, ok := res.(map[string]interface{})
	if !ok {
		return nil, ErrNotObject
	}
	return r, nil
}

// GetNodeStatus returns general status of a given node.
//
// For details see
// https://docs.near.org/docs/api/rpc/network#node-status
func (c *Connection) GetNodeStatus() (map[string]interface{}, error) {
	res, err := c.call("status", map[string]string{})
	if err != nil {
		return nil, err
	}
	r, ok := res.(map[string]interface{})
	if !ok {
		return nil, ErrNotObject
	}
	return r, nil
}

// GetAccountState returns basic account information for given accountID.
//
// For details see
// https://docs.near.org/docs/api/rpc/contracts#view-account
func (c *Connection) GetAccountState(accountID string) (map[string]interface{}, error) {
	res, err := c.call("query", map[string]string{
		"request_type": "view_account",
		"finality":     "final",
		"account_id":   accountID,
	})
	if err != nil {
		return nil, err
	}
	r, ok := res.(map[string]interface{})
	if !ok {
		return nil, ErrNotObject
	}
	return r, nil
}

// GetContractCode returns the contract code (Wasm binary) deployed to the account.
//
// For details see
// https://docs.near.org/docs/api/rpc/contracts#view-contract-code
func (c *Connection) GetContractCode(accountID string) (map[string]interface{}, error) {
	res, err := c.call("query", map[string]string{
		"request_type": "view_code",
		"finality":     "final",
		"account_id":   accountID,
	})
	if err != nil {
		return nil, err
	}
	r, ok := res.(map[string]interface{})
	if !ok {
		return nil, ErrNotObject
	}
	return r, nil
}

// SendTransaction sends a signed transaction and waits until the transaction
// is fully complete. Has a 10 second timeout.
//
// For details see
// https://docs.near.org/docs/develop/front-end/rpc#send-transaction-await
func (c *Connection) SendTransaction(signedTransaction []byte) (map[string]interface{}, error) {
	res, err := c.call("broadcast_tx_commit",
		base64.StdEncoding.EncodeToString(signedTransaction))
	if err != nil {
		return nil, err
	}
	r, ok := res.(map[string]interface{})
	if !ok {
		return nil, ErrNotObject
	}
	return r, nil
}

// SendTransactionAsync sends a signed transaction and immediately returns a
// transaction hash.
//
// For details see
// https://docs.near.org/docs/develop/front-end/rpc#send-transaction-async
func (c *Connection) SendTransactionAsync(signedTransaction []byte) (string, error) {
	res, err := c.call("broadcast_tx_async",
		base64.StdEncoding.EncodeToString(signedTransaction))
	if err != nil {
		return "", err
	}
	r, ok := res.(string)
	if !ok {
		return "", ErrNotString
	}
	return r, nil
}

// ViewAccessKey returns information about a single access key for given accountID and publicKey.
// The publicKey must have a signature algorithm prefix (like "ed25519:").
//
// For details see
// https://docs.near.org/docs/develop/front-end/rpc#view-access-key
func (c *Connection) ViewAccessKey(accountID, publicKey string) (map[string]interface{}, error) {
	res, err := c.call("query", map[string]string{
		"request_type": "view_access_key",
		"finality":     "final",
		"account_id":   accountID,
		"public_key":   publicKey,
	})
	if err != nil {
		return nil, err
	}
	r, ok := res.(map[string]interface{})
	if !ok {
		return nil, ErrNotObject
	}
	return r, nil
}

// GetTransactionLastResult decodes the last transaction result from a JSON
// map and tries to deterimine if we have an error condition.
func GetTransactionLastResult(txResult map[string]interface{}) (interface{}, error) {
	status, ok := txResult["status"].(map[string]interface{})
	if ok {
		enc, ok := status["SuccessValue"].(string)
		if ok {
			buf, err := base64.URLEncoding.DecodeString(enc)
			if err != nil {
				return nil, err
			}
			if len(buf) == 0 {
				return nil, nil
			}
			var jsn interface{}
			if err := json.Unmarshal(buf, &jsn); err != nil {
				// if we cannot unmarshal as JSON just return the buffer as a string
				return string(buf), nil
			}
			return jsn, nil
		} else if status["Failure"] != nil {
			jsn, err := json.MarshalIndent(status["Failure"], "", "  ")
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("failure:\n%s", string(jsn))
		}
	}
	return nil, nil
}
