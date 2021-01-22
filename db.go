package main

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/dataaccessobject/statedb"
	"github.com/incognitochain/incognito-chain/incdb"
	"github.com/incognitochain/incognito-chain/privacy/coin"
	"github.com/incognitochain/incognito-chain/wallet"
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
func saveCoins(paymentAddr string, tokenID string, coins []*coin.CoinV2) error {
	batch := coinDB.NewBatch()
	prefix := coinprefix(paymentAddr, tokenID)
	for _, coin := range coins {
		key := fmt.Sprintf("%s", coin.GetPublicKey().ToBytesS())
		keyBytes := append(prefix, []byte(key)...)
		var value []byte
		switch NODEMODE {
		case MODERPC:
			value = coin.Bytes()
		case MODELIGHT, MODESIM:
			wl, err := wallet.Base58CheckDeserialize(paymentAddr)
			if err != nil {
				return err
			}
			lastByte := wl.KeySet.PaymentAddress.Pk[len(wl.KeySet.PaymentAddress.Pk)-1]
			shardIDSender := common.GetShardIDFromLastByte(lastByte)
			tokenIDHash, err := common.Hash{}.NewHashFromStr(tokenID)
			if err != nil {
				return err
			}
			//statedb already save this coin so we only need to save the key on statedb as value to access it later via statedb
			value = statedb.GenerateOutputCoinObjectKey(*tokenIDHash, shardIDSender, coin.GetPublicKey().ToBytesS(), coin.Bytes()).Bytes()
		}
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
func getCoins(paymentAddr string, tokenID string, coinsPubkey []string) ([]*coin.CoinV2, error) {
	var result []*coin.CoinV2
	prefix := coinprefix(paymentAddr, tokenID)
	iter := coinDB.NewIteratorWithPrefix(prefix)
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

func checkCoinExist(paymentAddr string, tokenID string, coinPubkey string) bool {
	prefix := coinprefix(paymentAddr, tokenID)
	key := fmt.Sprintf("%s", coinPubkey)
	keyBytes := append(prefix, []byte(key)...)
	result, _ := coinDB.Has(keyBytes)
	return result
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
