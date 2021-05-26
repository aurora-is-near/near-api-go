package keystore

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadAccessKey(t *testing.T) {
	accountID := "test-account.testnet"
	filename := filepath.Join("testdata", accountID+".json")
	_, err := loadKeyPair(filename, accountID)
	if err != nil {
		t.Fatal(err)
	}

	accountID = "evm.test-account.testnet"
	filename = filepath.Join("testdata", accountID+".json")
	_, err = loadKeyPair(filename, accountID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateWriteRead(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "keystore_test")
	if err != nil {
		t.Fatalf("os.TempDir() failed: %v", err)
	}
	defer os.RemoveAll(tmpdir)
	// generate
	accountID := "test-account.testnet"
	kp1, err := GenerateEd25519KeyPair(accountID)
	if err != nil {
		t.Fatal(err)
	}
	// write
	filename := filepath.Join(tmpdir, accountID+".json")
	if err := kp1.write(filename); err != nil {
		t.Fatal(err)
	}
	// read
	kp2, err := loadKeyPair(filename, accountID)
	if err != nil {
		t.Fatal(err)
	}
	// compare
	if !reflect.DeepEqual(kp1, kp2) {
		t.Fatal("kp1 != kp2")
	}
}
