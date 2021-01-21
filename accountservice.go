package main

import (
	"sync"
	"time"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/privacy/key"
	"github.com/incognitochain/incognito-chain/wallet"
)

type Account struct {
	ShardID        byte
	PAstr          string //PaymentAddressString
	PaymentAddress key.PaymentAddress
	Viewkey        key.ViewingKey
	OTAKey         key.PrivateOTAKey
}

type AccountState struct {
	Account *Account
	Balance uint64
	isReady bool

	lock sync.RWMutex
	//map[tokenID][]coinHash
	PendingCoins   map[string][]string //wait for tx to confirm
	AvaliableCoins map[string][]string //avaliable to use
	EncryptedCoins map[string][]string //encrypted, dont know whether been used
}

var accountListLck sync.RWMutex
var accountList map[string]*AccountState
var currentAccount string

func (as *AccountState) init() {
	as.Balance = 0
	as.isReady = false
	as.PendingCoins = make(map[string][]string)
	as.AvaliableCoins = make(map[string][]string)
	as.EncryptedCoins = make(map[string][]string)
}

func importAccount(name string, paymentAddr string, viewKey string, OTAKey string) error {
	accountListLck.Lock()
	defer accountListLck.Unlock()
	accState := new(AccountState)
	accState.init()
	wl, err := wallet.Base58CheckDeserialize(paymentAddr)
	if err != nil {
		return err
	}
	acc := new(Account)
	acc.PaymentAddress = wl.KeySet.PaymentAddress
	lastByte := wl.KeySet.PaymentAddress.Pk[len(wl.KeySet.PaymentAddress.Pk)-1]
	shardID := common.GetShardIDFromLastByte(lastByte)
	acc.ShardID = shardID
	accState.Account = acc
	accountList[name] = accState
	return nil
}

func initAccountService() error {
	accountList = make(map[string]*AccountState)
	accs, err := loadAccountsFromDB()
	if err != nil {
		return err
	}
	accountListLck.Lock()
	for accName, acc := range accs {
		accState := new(AccountState)
		accState.init()
		wl, err := wallet.Base58CheckDeserialize(acc.PAstr)
		if err != nil {
			return err
		}
		acc.PaymentAddress = wl.KeySet.PaymentAddress
		lastByte := wl.KeySet.PaymentAddress.Pk[len(wl.KeySet.PaymentAddress.Pk)-1]
		shardID := common.GetShardIDFromLastByte(lastByte)
		acc.ShardID = shardID
		accState.Account = acc
		accountList[accName] = accState
	}
	accountListLck.Unlock()
	return nil
}

func scanForNewCoins() {
	for {
		if len(accountList) == 0 {
			time.Sleep(15 * time.Second)
			continue
		}
		accountListLck.RLock()
		for name, account := range accountList {
			_ = account
			_ = name
		}
		accountListLck.RUnlock()
		time.Sleep(40 * time.Second)
	}
}

func getAccountList() map[string]string {
	var result map[string]string
	result = make(map[string]string)
	accountListLck.RLock()
	for name, account := range accountList {
		result[name] = account.Account.PAstr
	}
	accountListLck.RUnlock()
	return result
}

func getAllBalance() map[string]uint64 {
	var result map[string]uint64
	accountListLck.RLock()
	result = make(map[string]uint64)
	for name, account := range accountList {
		result[name] = account.Balance
	}
	accountListLck.RUnlock()
	return result
}
