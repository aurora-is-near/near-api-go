/*
 * @Author: 胡勇超 huyongchao98@163.com
 * @Date: 2023-04-17 18:41:57
 * @LastEditors: 胡勇超 huyongchao98@163.com
 * @LastEditTime: 2023-04-17 18:42:03
 * @FilePath: /NearMPCWallet/new-near-api-go/testUtil.go
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
package near

import (
	"time"

	"github.com/aurora-is-near/near-api-go/keystore"
	"github.com/btcsuite/btcutil/base58"
)

func BuildAccount() Account {
	rpcEndpoint := "https://rpc.testnet.near.org"
	mainAccountID := "testdafa.testnet"

	connection := NewConnectionWithTimeout(rpcEndpoint, time.Second*10)

	keyPair := keystore.Ed25519KeyPair{
		AccountID:      mainAccountID,
		PublicKey:      "ed25519:6wTjVszCPsk6ZGjVNk4tTjHpY2A7AMypfapcWCfo8umZ",
		PrivateKey:     "ed25519:3G7BmuSTuo825Y1kCTyRwMm9incjuNDcf24p42pKi9PgDv3JyvPzJT4Kb88mRHR3KyPDXNu2Gsy3w8dRMAR6eKoM",
		Ed25519PubKey:  base58.Decode("6wTjVszCPsk6ZGjVNk4tTjHpY2A7AMypfapcWCfo8umZ"),
		Ed25519PrivKey: base58.Decode("3G7BmuSTuo825Y1kCTyRwMm9incjuNDcf24p42pKi9PgDv3JyvPzJT4Kb88mRHR3KyPDXNu2Gsy3w8dRMAR6eKoM"),
	}

	a := Account{
		conn: connection,
		kp:   &keyPair,
	}

	a.accessKeyByPublicKeyCache = make(map[string]map[string]interface{})
	return a
}
