package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/incognitochain/incognito-chain/incdb"
	"github.com/incognitochain/incognito-chain/privacy/coin"
	"golang.org/x/crypto/sha3"
)

var accountDB incdb.Database
var keyimageDB incdb.Database
var coinDB incdb.Database

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

func initcoinDB(datadir string) error {
	temp, err := incdb.Open("leveldb", filepath.Join(datadir, "coins"))
	if err != nil {
		return err
	}
	coinDB = temp
	return nil
}

func saveAccount(name string, account *Account) error {
	accountBytes := []byte{}
	accountBytes = append(accountBytes, account.Viewkey.Rk...)
	accountBytes = append(accountBytes, account.OTAKey...)
	accountBytes = append(accountBytes, []byte(account.PAstr)...)
	key := append(DB_ACCOUNTKEY, []byte(name)...)
	err := accountDB.Put(key, accountBytes)
	if err != nil {
		return err
	}
	return nil
}

func deleteAccount(name string) error {
	key := append(DB_ACCOUNTKEY, []byte(name)...)
	err := accountDB.Delete(key)
	if err != nil {
		return err
	}
	return nil
}

func loadAccountsFromDB() (map[string]*Account, error) {
	var result map[string]*Account
	result = make(map[string]*Account)
	iter := accountDB.NewIteratorWithPrefix(DB_ACCOUNTKEY)
	for iter.Next() {
		acc := new(Account)
		v := iter.Value()
		acc.Viewkey.Rk = v[:32]
		acc.OTAKey = v[32:64]
		acc.PAstr = string(v[64:])
		result[string(iter.Key()[len(DB_ACCOUNTKEY):])] = acc
	}
	iter.Release()
	err := iter.Error()
	return result, err
}

func saveAccountCoinState(paymentAddr string, coinState AccountCoinState) error {
	coinStateBytes, err := json.Marshal(coinState)
	if err != nil {
		return err
	}
	key := append(DB_COINSTATEKEY, []byte(paymentAddr)...)
	err = accountDB.Put(key, coinStateBytes)
	if err != nil {
		return err
	}
	return nil
}

func loadAccountCoinState(paymentAddr string) (*AccountCoinState, error) {
	var coinState AccountCoinState
	key := append(DB_COINSTATEKEY, []byte(paymentAddr)...)
	coinStateBytes, err := accountDB.Get(key)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(coinStateBytes, &coinState)
	if err != nil {
		return nil, err
	}
	return &coinState, nil
}

func deleteAccountCoinState(paymentAddr string) error {
	key := append(DB_COINSTATEKEY, []byte(paymentAddr)...)
	err := accountDB.Delete(key)
	if err != nil {
		return err
	}
	return nil
}
func saveKeyImages(keyImages map[string]string, tokenID string, paymentAddr string) error {
	batch := keyimageDB.NewBatch()
	prefix := coinprefix(paymentAddr, tokenID)
	for coinPubkeyHash, keyImage := range keyImages {
		key := coinPubkeyHash
		keyBytes := append(prefix, []byte(key)...)
		err := batch.Put(keyBytes, []byte(keyImage))
		if err != nil {
			return err
		}
	}
	if err := batch.Write(); err != nil {
		return err
	}
	return nil
}

func getAllKeyImages(paymentAddr string, tokenID string) (map[string][]byte, error) {
	var result map[string][]byte
	result = make(map[string][]byte)
	prefix := coinprefix(paymentAddr, tokenID)
	iter := keyimageDB.NewIteratorWithPrefix(prefix)
	for iter.Next() {
		v := iter.Value()
		result[string(iter.Key()[8:])] = v
	}
	iter.Release()
	err := iter.Error()
	return result, err
}

func getUnusedKeyImages(paymentAddr string, tokenID string) (map[string][]byte, error) {
	var result map[string][]byte
	result = make(map[string][]byte)
	prefix := coinprefix(paymentAddr, tokenID)
	iter := keyimageDB.NewIteratorWithPrefix(prefix)
	for iter.Next() {
		v := iter.Value()
		if bytes.Equal(v, usedkeyimage) {
			continue
		}
		result[string(iter.Key()[8:])] = v
	}
	iter.Release()
	err := iter.Error()
	return result, err
}

func updateUsedKeyImages(paymentAddr string, tokenID string, coinsPubkey []string) error {
	batch := keyimageDB.NewBatch()
	prefix := coinprefix(paymentAddr, tokenID)
	for _, coinPK := range coinsPubkey {
		key := coinPK
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
func saveCoins(paymentAddr string, tokenID string, coins []coin.PlainCoin) error {
	batch := coinDB.NewBatch()
	prefix := coinprefix(paymentAddr, tokenID)
	for _, coin := range coins {
		key := hex.EncodeToString(coin.GetPublicKey().ToBytesS())
		keyBytes := append(prefix, []byte(key)...)
		var value []byte
		value = coin.Bytes()
		if coin.GetVersion() != 2 {
			panic("oops")
		}
		fmt.Println("len(keyBytes)", len(keyBytes))
		if err := batch.Put(keyBytes, value); err != nil {
			return err
		}
	}

	if err := batch.Write(); err != nil {
		return err
	}
	return nil
}

//this function is used when RPCMODE
func getCoinsByCoinPubkey(paymentAddr string, tokenID string, coinsPubkey []string) ([]coin.PlainCoin, error) {
	var result []coin.PlainCoin
	for _, coinPK := range coinsPubkey {
		prefix := coinprefix(paymentAddr, tokenID)
		keyBytes := append(prefix, []byte(coinPK)...)
		coinBytes, err := coinDB.Get(keyBytes)
		if err != nil {
			fmt.Println(err)
			continue
		}
		newCoin := new(coin.CoinV2)
		err = newCoin.SetBytes(coinBytes)
		if err != nil {
			panic(err)
		}
		result = append(result, newCoin)
	}
	return result, nil
}

func checkCoinExist(paymentAddr string, tokenID string, coinPubkey string) bool {
	prefix := coinprefix(paymentAddr, tokenID)
	keyBytes := append(prefix, []byte(coinPubkey)...)
	result, err := coinDB.Has(keyBytes)
	if err != nil {
		panic(err)
	}
	return result
}

// func getUnusedCoins(paymentAddr string,tokenID string) []
//last 8 bytes of hash of paymentAddr&tokenID
func coinprefix(paymentAddr string, tokenID string) []byte {
	// var result []byte
	prefix := []byte{}
	prefix = append(prefix, []byte(paymentAddr)...)
	prefix = append(prefix, []byte(tokenID)...)
	result := sha3.Sum256(prefix)
	return result[24:]
}

func checkCoinExistAndSave(paymentAddr string, tokenID string, coins []coin.PlainCoin) ([]string, error) {
	var newCoins []string //[]coinPubkey
	batch := coinDB.NewBatch()
	prefix := coinprefix(paymentAddr, tokenID)
	for _, coin := range coins {
		key := hex.EncodeToString(coin.GetPublicKey().ToBytesS())
		keyBytes := append(prefix, []byte(key)...)
		if !checkCoinExist(paymentAddr, tokenID, key) {
			var value []byte
			value = coin.Bytes()
			if coin.GetVersion() != 2 {
				panic("oops")
			}
			fmt.Println("len(keyBytes)", len(keyBytes))
			if err := batch.Put(keyBytes, value); err != nil {
				return nil, err
			}
			newCoins = append(newCoins, key)
		}
	}

	if err := batch.Write(); err != nil {
		return nil, err
	}
	return newCoins, nil
}
