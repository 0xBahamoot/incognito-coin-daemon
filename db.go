package main

import (
	"bytes"
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

func saveAccount(name string, account *Account) error {
	accountBytes := []byte{}
	accountBytes = append(accountBytes, account.Viewkey.Rk...)
	accountBytes = append(accountBytes, account.OTAKey...)
	accountBytes = append(accountBytes, []byte(account.PAstr)...)
	err := accountDB.Put([]byte(name), accountBytes)
	if err != nil {
		return err
	}
	return nil
}

func deleteAccount(name string) error {
	err := accountDB.Delete([]byte(name))
	if err != nil {
		return err
	}
	return nil
}

func loadAccountsFromDB() (map[string]*Account, error) {
	var result map[string]*Account
	result = make(map[string]*Account)
	// for _, account := range accountList {
	// 	_ = account
	// }
	return result, nil
}

func saveKeyImages(keyImages map[string][]byte, tokenID string, paymentAddrHash string) error {
	batch := keyimageDB.NewBatch()
	prefix := coinprefix(paymentAddrHash, tokenID)
	for commitmentHash, keyImage := range keyImages {
		key := fmt.Sprintf("%s", commitmentHash)
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
		v := iter.Value()
		result[string(iter.Key()[8:])] = v
	}
	iter.Release()
	err := iter.Error()
	return result, err
}

func getUnusedKeyImages(paymentAddrHash string, tokenID string) (map[string][]byte, error) {
	var result map[string][]byte
	result = make(map[string][]byte)
	prefix := coinprefix(paymentAddrHash, tokenID)
	iter := keyimageDB.NewIteratorWithPrefix(prefix)
	for iter.Next() {
		v := iter.Value()
		if bytes.Compare(v, usedkeyimage) == 0 {
			continue
		}
		result[string(iter.Key()[8:])] = v
	}
	iter.Release()
	err := iter.Error()
	return result, err
}

func updateUsedKeyImages(paymentAddrHash string, tokenID string, coinsPubkey []string) error {
	batch := keyimageDB.NewBatch()
	prefix := coinprefix(paymentAddrHash, tokenID)
	for _, coinPK := range coinsPubkey {
		key := fmt.Sprintf("%s", coinPK)
		keyBytes := append(prefix, []byte(key)...)
		if err := batch.Put(keyBytes, usedkeyimage); err != nil {
			return err
		}
	}
	if err := batch.Write(); err != nil {
		return err
	}
	return nil
}

//this function is used when RPCMODE
func saveCoins(paymentAddrHash string, tokenID string, coins []*coin.CoinV2) error {
	batch := RPCCoinDB.NewBatch()
	prefix := coinprefix(paymentAddrHash, tokenID)
	for _, coin := range coins {
		key := fmt.Sprintf("%s", coin.GetPublicKey().ToBytesS())
		keyBytes := append(prefix, []byte(key)...)
		if err := batch.Put(keyBytes, coin.Bytes()); err != nil {
			return err
		}
	}

	if err := batch.Write(); err != nil {
		return err
	}
	return nil
}

//this function is used when RPCMODE
func getCoins(paymentAddrHash string, tokenID string, coinsPubkey []string) ([]*coin.CoinV2, error) {
	var result []*coin.CoinV2
	prefix := coinprefix(paymentAddrHash, tokenID)
	iter := RPCCoinDB.NewIteratorWithPrefix(prefix)
	for iter.Next() {
		v := iter.Value()
		if bytes.Compare(v, usedkeyimage) == 0 {
			continue
		}
		newCoin := new(coin.CoinV2)
		newCoin.SetBytes(v)
		result = append(result, newCoin)
	}
	iter.Release()
	err := iter.Error()
	return result, err
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
