package main

import (
	"fmt"
	"path/filepath"

	"github.com/incognitochain/incognito-chain/incdb"
	"github.com/incognitochain/incognito-chain/privacy/coin"
	"golang.org/x/crypto/sha3"
)

var accountDB incdb.Database
var keyimageDB incdb.Database
var RPCCoinDB incdb.Database

func initAccountDB(datadir string) error {
	temp, err := incdb.Open("leveldb", filepath.Join(datadir, "accounts"))
	if err != nil {
		return err
	}
	accountDB = temp
	return nil
}

func initKeyimageDB(datadir string) error {
	temp, err := incdb.Open("leveldb", filepath.Join(datadir, "keyimages"))
	if err != nil {
		return err
	}
	keyimageDB = temp
	return nil
}

func initRPCCoinDB(datadir string) error {
	temp, err := incdb.Open("leveldb", filepath.Join(datadir, "coins"))
	if err != nil {
		return err
	}
	RPCCoinDB = temp
	return nil
}

func saveAccount(account Account) error {
	// accountBytes :=
	return nil
}

func loadAccountsFromDB() ([]*Account, error) {
	var result []*Account
	accountListLck.RLock()
	for _, account := range accountList {
		_ = account
	}
	accountListLck.RUnlock()
	return result, nil
}

func saveKeyImages(keyImages map[string][]byte, tokenID string, paymentAddrHash string) error {
	batch := keyimageDB.NewBatch()
	prefix := coinprefix(paymentAddrHash, tokenID)
	for commitmentHash, keyImage := range keyImages {
		key := fmt.Sprintf("-%s", commitmentHash)
		keyBytes := append(prefix, []byte(key)...)
		err := batch.Put(keyBytes, keyImage)
		if err != nil {
			return err
		}
	}
	if err := batch.Write(); err != nil {
		return err
	}
	return nil
}

func getAllKeyImages(paymentAddrHash string, tokenID string) (map[string][]byte, error) {
	var result map[string][]byte
	result = make(map[string][]byte)
	prefix := coinprefix(paymentAddrHash, tokenID)
	iter := keyimageDB.NewIteratorWithPrefix(prefix)
	for iter.Next() {

	}
	iter.Release()
	err := iter.Error()

	return result, err
}

func getUnusedKeyImages(paymentAddrHash string, tokenID string) (map[string][]byte, error) {
	var result map[string][]byte
	result = make(map[string][]byte)
	prefix := coinprefix(paymentAddrHash, tokenID)

	return result, nil
}

func updateUsedKeyImages(paymentAddrHash string, tokenID string, coinHashes []string) error {
	batch := keyimageDB.NewBatch()
	prefix := coinprefix(paymentAddrHash, tokenID)
	for _, coin := range coinHashes {

	}
	if err := batch.Write(); err != nil {
		return err
	}
	return nil
}

//this function is used when RPCMODE
func saveCoins(paymentAddrHash string, tokenID string, coins []*coin.PlainCoin) error {
	prefix := coinprefix(paymentAddrHash, tokenID)
	return nil
}

// func getUnusedCoins(paymentAddrHash string,tokenID string) []
//last 8 bytes of hash of paymentAddrHash&tokenID
func coinprefix(paymentAddrHash string, tokenID string) []byte {
	// var result []byte
	prefix := []byte{}
	prefix = append(prefix, []byte(paymentAddrHash)...)
	prefix = append(prefix, []byte(tokenID)...)
	result := sha3.Sum256(prefix)
	return result[24:]
}
