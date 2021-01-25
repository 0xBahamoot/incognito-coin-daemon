package main

import (
	"encoding/hex"
	"errors"
	"fmt"
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
	Account          *Account
	Balance          uint64
	AvailableBalance uint64
	isReady          bool

	lock sync.RWMutex
	//map[tokenID][]coinpubkey
	PendingCoins   map[string][]string //wait for tx to confirm
	AvailableCoins map[string][]string //avaliable to use
	EncryptedCoins map[string][]string //encrypted, dont know whether been used
}

var accountListLck sync.RWMutex
var accountList map[string]*AccountState
var currentAccount string

func (as *AccountState) init() {
	as.Balance = 0
	as.isReady = false
	as.PendingCoins = make(map[string][]string)
	as.AvailableCoins = make(map[string][]string)
	as.EncryptedCoins = make(map[string][]string)
}

func importAccount(name string, paymentAddr string, viewKey string, OTAKey string) error {
	accountListLck.Lock()
	defer accountListLck.Unlock()
	if _, ok := accountList[name]; ok {
		return errors.New("this account name already existed")
	}
	for name, acc := range accountList {
		if acc.Account.PAstr == paymentAddr {
			return errors.New("this account already added as " + name)
		}
	}
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
	viewKeyBytes, _ := hex.DecodeString(viewKey)
	acc.Viewkey.Rk = viewKeyBytes
	acc.Viewkey.Pk = wl.KeySet.PaymentAddress.Pk
	OTAKeyBytes, _ := hex.DecodeString(OTAKey)
	acc.OTAKey = OTAKeyBytes
	acc.PAstr = paymentAddr
	accState.Account = acc
	accountList[name] = accState

	if err := saveAccount(name, acc); err != nil {
		return err
	}
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
	go scanForNewCoins()
	return nil
}

func scanForNewCoins() {
	for {
		if len(accountList) == 0 {
			time.Sleep(20 * time.Second)
			continue
		}
		accountListLck.RLock()
		////////////////////////////////////
		// add more token
		var wg sync.WaitGroup
		var tokenID *common.Hash
		if tokenID == nil {
			tokenID = &common.Hash{}
			tokenID.SetBytes(common.PRVCoinID[:])
		}

		for name, account := range accountList {
			wg.Add(1)
			go func(n string, a *AccountState) {
				defer wg.Done()
				a.lock.Lock()
				fmt.Printf("scan coins for account %s\n", n)
				a.isReady = false
				coinList, err := GetCoinsByPaymentAddress(a.Account.PAstr, a.Account.OTAKey, nil)
				if err != nil {
					fmt.Println(err)
				}
				if len(coinList) > 0 {
					coins, err := checkCoinExistAndSave(a.Account.PAstr, tokenID.String(), coinList)
					if err != nil {
						panic(err)
					}
					a.EncryptedCoins[tokenID.String()] = append(a.EncryptedCoins[tokenID.String()], coins...)
				}
				a.lock.Unlock()
				a.isReady = true
				fmt.Printf("account %s is ready\n", n)
			}(name, account)
		}
		wg.Wait()
		////////////////
		accountListLck.RUnlock()

		time.Sleep(20 * time.Second)
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

func getBalance(accountName string) uint64 {
	return accountList[accountName].AvailableBalance
}
