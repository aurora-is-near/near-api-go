// Package keystore implements an unencrypted file system key store.
package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aurora-is-near/near-api-go/utils"
)

// Ed25519KeyPair is an Ed25519 key pair.
type Ed25519KeyPair struct {
	AccountID      string             `json:"account_id"`
	PublicKey      string             `json:"public_key"`
	PrivateKey     string             `json:"private_key,omitempty"`
	SecretKey      string             `json:"secret_key,omitempty"`
	Ed25519PubKey  ed25519.PublicKey  `json:"-"`
	Ed25519PrivKey ed25519.PrivateKey `json:"-"`
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair for accountID.
func GenerateEd25519KeyPair(accountID string) (*Ed25519KeyPair, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return KeyPairFromPrivateKey(accountID, privateKey), nil
}

// ParseEd25519PrivateKey parses a private key string and returns an ed25519.PrivateKey.
func ParseEd25519PrivateKey(privateKeyString string) (ed25519.PrivateKey, error) {
	return utils.Ed25519PrivateKeyFromString(privateKeyString)
}

// KeyPairFromPrivateKey creates a key-pair given an accountID and a private key.
func KeyPairFromPrivateKey(accountID string, privateKey ed25519.PrivateKey) *Ed25519KeyPair {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &Ed25519KeyPair{
		AccountID:      accountID,
		Ed25519PubKey:  publicKey,
		Ed25519PrivKey: privateKey,
		PublicKey:      utils.Ed25519PublicKeyToString(publicKey),
		PrivateKey:     utils.Ed25519PrivateKeyToString(privateKey),
	}
}

func (kp *Ed25519KeyPair) write(filename string) error {
	data, err := json.Marshal(kp)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0600)
}

// Write the Ed25519 key pair to the unencrypted file system key store with
// networkID and return the filename of the written file.
func (kp *Ed25519KeyPair) Write(networkID string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	filename := filepath.Join(home, ".near-credentials", networkID, kp.AccountID+".json")
	return filename, kp.write(filename)
}

// LoadKeyPairFromPath reads the Ed25519 key pair for the given ccountID from path
// returns it.
func LoadKeyPairFromPath(path, accountID string) (*Ed25519KeyPair, error) {

	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kp Ed25519KeyPair
	err = json.Unmarshal(buf, &kp)
	if err != nil {
		return nil, err
	}
	// account ID
	if kp.AccountID != accountID {
		return nil, fmt.Errorf("keystore: parsed account_id '%s' does not match with accountID '%s'",
			kp.AccountID, accountID)
	}
	// public key
	kp.Ed25519PubKey, err = utils.Ed25519PublicKeyFromString(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keystore: invalid public_key: %w", err)
	}
	// private key
	var privateKey ed25519.PrivateKey
	if len(kp.PrivateKey) > 0 && len(kp.SecretKey) > 0 {
		return nil, fmt.Errorf("keystore: private_key and secret_key are defined at the same time: %s", path)
	} else if len(kp.PrivateKey) > 0 {
		privateKey, err = utils.Ed25519PrivateKeyFromString(kp.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("keystore: invalid private_key: %w", err)
		}
	} else { // secret_key
		privateKey, err = utils.Ed25519PrivateKeyFromString(kp.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("keystore: invalid secret_key: %w", err)
		}
	}
	kp.Ed25519PrivKey = privateKey

	// make sure keys match
	if !bytes.Equal(kp.Ed25519PubKey, kp.Ed25519PrivKey.Public().(ed25519.PublicKey)) {
		return nil, fmt.Errorf("keystore: public_key does not match private_key: %s", path)
	}
	return &kp, nil
}
