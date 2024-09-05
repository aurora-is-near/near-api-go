// Package near allows to interact with the NEAR platform via RPC calls.
package near

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aurora-is-near/go-jsonrpc/v3"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Connection allows to do JSON-RPC to a NEAR endpoint.
type Connection struct {
	OTLPEnabled bool
	c           jsonrpc.RPCClient
}

// NewConnection returns a new connection for JSON-RPC calls to the NEAR
// endpoint with the given nodeURL.
func NewConnection(nodeURL string) *Connection {
	return NewConnectionWithTimeout(nodeURL, 0)
}

func NewConnectionWithOTLPTracing(nodeURL string, timeout time.Duration) *Connection {
	return &Connection{
		OTLPEnabled: true,
		c: jsonrpc.NewClientWithOpts(nodeURL, &jsonrpc.RPCClientOpts{
			HTTPClient: &http.Client{
				Timeout:   timeout,
				Transport: otelhttp.NewTransport(http.DefaultTransport),
			},
		}),
	}
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
func (c *Connection) call(ctx context.Context, method string, params ...interface{}) (interface{}, error) {
	var span trace.Span
	if c.OTLPEnabled {
		ctx, span = otel.GetTracerProvider().Tracer("near-api-go").
			Start(
				ctx,
				method,
				trace.WithSpanKind(trace.SpanKindInternal),
				trace.WithAttributes(
					attribute.String("method", method),
					attribute.String("params", fmt.Sprintf("%v", params)),
				),
			)
		defer span.End()
	}

	start := time.Now()
	res, err := c.c.CallCtx(ctx, method, params...)
	if err != nil {
		return nil, err
	}
	if res.Error != nil {
		span.RecordError(res.Error)

		if res.Error.Data != nil {
			if c.OTLPEnabled {
				span.SetStatus(codes.Error, fmt.Sprintf("near: jsonrpc: %d: %s: %v", res.Error.Code, res.Error.Message, res.Error.Data))
			}
			return nil, fmt.Errorf("near: jsonrpc: %d: %s: %v (after %s)",
				res.Error.Code, res.Error.Message, res.Error.Data, time.Since(start))
		}
		if c.OTLPEnabled {
			span.SetStatus(codes.Error, fmt.Sprintf("near: jsonrpc: %d: %s", res.Error.Code, res.Error.Message))
		}
		return nil, fmt.Errorf("near: jsonrpc: %d: %s (after %s)",
			res.Error.Code, res.Error.Message, time.Since(start))
	}
	if res.Result == nil {
		if c.OTLPEnabled {
			span.SetStatus(codes.Error, "JSON-RPC result is nil")
		}
		return nil, fmt.Errorf("near: JSON-RPC result is nil (after %s)", time.Since(start))
	}

	if c.OTLPEnabled {
		span.SetStatus(codes.Ok, "Success")
		span.SetAttributes(attribute.String("result", fmt.Sprintf("%v", res.Result)))
	}
	return res.Result, nil
}

// Call performs a generic call of the given NEAR JSON-RPC method with params.
// It handles all possible error cases and returns the result (which cannot be nil).
func (c *Connection) Call(ctx context.Context, method string, params ...interface{}) (interface{}, error) {
	return c.call(ctx, method, params...)
}

// Block queries network and returns latest block.
//
// For details see https://docs.near.org/docs/interaction/rpc#block
func (c *Connection) Block(ctx context.Context) (map[string]interface{}, error) {
	res, err := c.call(ctx, "block", map[string]string{
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

// Block with given blockHash queries network and returns block with given hash.
//
// For details see https://docs.near.org/api/rpc/block-chunk#block-details
func (c *Connection) GetBlockByHash(ctx context.Context, blockHash string) (map[string]interface{}, error) {
	res, err := c.call(ctx, "block", map[string]string{
		"block_id": blockHash,
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

// Block with given blockId queries network and returns block with given ID.
//
// For details see https://docs.near.org/api/rpc/block-chunk#block-details
func (c *Connection) GetBlockByID(ctx context.Context, blockID uint64) (map[string]interface{}, error) {
	res, err := c.call(ctx, "block", map[string]interface{}{
		"block_id": blockID,
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
func (c *Connection) GetNodeStatus(ctx context.Context) (map[string]interface{}, error) {
	res, err := c.call(ctx, "status", map[string]string{})
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
func (c *Connection) GetAccountState(ctx context.Context, accountID string) (map[string]interface{}, error) {
	res, err := c.call(ctx, "query", map[string]string{
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
func (c *Connection) GetContractCode(ctx context.Context, accountID string) (map[string]interface{}, error) {
	res, err := c.call(ctx, "query", map[string]string{
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
func (c *Connection) SendTransaction(ctx context.Context, signedTransaction []byte) (map[string]interface{}, error) {
	res, err := c.call(ctx, "broadcast_tx_commit",
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
func (c *Connection) SendTransactionAsync(ctx context.Context, signedTransaction []byte) (string, error) {
	res, err := c.call(ctx, "broadcast_tx_async",
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
func (c *Connection) ViewAccessKey(ctx context.Context, accountID, publicKey string) (map[string]interface{}, error) {
	res, err := c.call(ctx, "query", map[string]string{
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

// ViewAccessKeyList returns all access keys for the given accountID.
//
// For details see
// https://docs.near.org/docs/api/rpc/access-keys#view-access-key-list
func (c *Connection) ViewAccessKeyList(ctx context.Context, accountID string) (map[string]interface{}, error) {
	res, err := c.call(ctx, "query", map[string]string{
		"request_type": "view_access_key_list",
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

// GetTransactionDetails returns information about a single transaction.
//
// For details see
// https://docs.near.org/api/rpc/transactions#transaction-status
func (c *Connection) GetTransactionDetails(ctx context.Context, txHash, senderAccountId string) (map[string]interface{}, error) {
	params := []interface{}{txHash, senderAccountId}

	res, err := c.call(ctx, "tx", params)
	if err != nil {
		return nil, err
	}

	r, ok := res.(map[string]interface{})
	if !ok {
		return nil, ErrNotObject
	}

	return r, nil
}

// GetTransactionDetailsWithWait returns information about a single transaction after waiting for the specified execution status.
//
// For details see
// https://docs.near.org/api/rpc/transactions#transaction-status
func (c *Connection) GetTransactionDetailsWithWait(ctx context.Context, txHash, senderAccountId string, waitUntil TxExecutionStatus) (map[string]interface{}, error) {
	params := map[string]interface{}{
		"tx_hash":           txHash,
		"sender_account_id": senderAccountId,
		"wait_until":        waitUntil,
	}

	res, err := c.call(ctx, "tx", params)
	if err != nil {
		return nil, err
	}

	r, ok := res.(map[string]interface{})
	if !ok {
		return nil, ErrNotObject
	}

	return r, nil
}

// GetTransactionDetailsWithReceipts returns information about a single transaction with receipts
//
// For details see
// https://docs.near.org/api/rpc/transactions#transaction-status-with-receipts
func (c *Connection) GetTransactionDetailsWithReceipts(ctx context.Context, txHash, senderAccountId string) (map[string]interface{}, error) {
	params := []interface{}{txHash, senderAccountId}

	res, err := c.call(ctx, "EXPERIMENTAL_tx_status", params)
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
