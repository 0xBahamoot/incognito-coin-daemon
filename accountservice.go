package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
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
	Balance          map[string]uint64
	AvailableBalance map[string]uint64
	isReady          bool

	lock         sync.RWMutex
	PendingCoins []string //wait for tx to confirm
	//map[tokenID][]coinpubkey
	AvailableCoins   map[string][]string //avaliable to use
	EncryptedCoins   map[string][]string //encrypted, dont know whether been used
	AvlCoinsKeyimage map[string]string
	CoinsValue       map[string]uint64
	CTerminate       chan struct{}
}

var accountListLck sync.RWMutex
var accountList map[string]*AccountState
var currentAccount string

func (as *AccountState) init() {
	as.isReady = false
	as.Balance = make(map[string]uint64)
	as.AvailableBalance = make(map[string]uint64)
	as.AvailableCoins = make(map[string][]string)
	as.EncryptedCoins = make(map[string][]string)
	as.AvlCoinsKeyimage = make(map[string]string)
	as.CoinsValue = make(map[string]uint64)
	as.CTerminate = make(chan struct{})
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

	go accState.WatchBalance()
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
		go accState.WatchBalance()
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
				coinList, err := GetCoinsByPaymentAddress(a.Account, nil)
				if err != nil {
					fmt.Println(err)
				}
				if len(coinList) > 0 {
					coins, err := checkCoinExistAndSave(a.Account.PAstr, tokenID.String(), coinList)
					if err != nil {
						panic(err)
					}
					a.EncryptedCoins[tokenID.String()] = append(a.EncryptedCoins[tokenID.String()], coins...)
					for _, coin := range coinList {
						key := fmt.Sprintf("%s", coin.GetPublicKey().ToBytesS())
						a.CoinsValue[key] = coin.GetValue()
					}
				}
				a.lock.Unlock()
				a.isReady = true
				fmt.Printf("account %s is ready\n", n)
			}(name, account)
		}
		wg.Wait()
		////////////////
		accountListLck.RUnlock()

		time.Sleep(5 * time.Second)
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

func getAllBalance() map[string]map[string]uint64 {
	accountListLck.RLock()
	result := make(map[string]map[string]uint64)
	for name, account := range accountList {
		result[name] = make(map[string]uint64)
		for token, balance := range account.Balance {
			result[name][token] = balance
		}
	}
	accountListLck.RUnlock()
	return result
}

func (acc *AccountState) GetBalance() map[string]uint64 {
	result := make(map[string]uint64)
	for token, balance := range acc.Balance {
		result[token] = balance
	}
	return result
}

func (acc *AccountState) UpdateDecryptedCoin(coinList map[string][]string, keyimages map[string]string) error {
	acc.lock.Lock()
	acc.isReady = false
	for token, coins := range coinList {
		newCoinList := []string{}
		tokenkms := make(map[string]string)
		for _, encoin := range acc.EncryptedCoins[token] {
			stillEncrypted := true
			for _, decoin := range coins {
				if decoin == encoin {
					stillEncrypted = false
					tokenkms[decoin] = keyimages[decoin]
					break
				}
			}
			if stillEncrypted {
				newCoinList = append(newCoinList, encoin)
			}
		}
		acc.EncryptedCoins[token] = newCoinList
		acc.AvailableCoins[token] = append(acc.AvailableCoins[token], coins...)

		if err := saveKeyImages(tokenkms, token, acc.Account.PAstr); err != nil {
			panic(err)
		}
	}
	acc.AvlCoinsKeyimage = keyimages
	acc.lock.Unlock()
	acc.isReady = true
	return nil
}

func (acc *AccountState) WatchBalance() {
	tc := time.NewTicker(defaultBalanceWatchInterval)
	for {
		select {
		case <-tc.C:
			if len(acc.AvailableCoins) == 0 {
				continue
			}
			acc.lock.RLock()
			keyimagesToCheck := make(map[string][]string)
			for token, coins := range acc.AvailableCoins {
				for _, coin := range coins {
					keyimagesToCheck[token] = append(keyimagesToCheck[token], base58.Base58Check{}.Encode([]byte(acc.AvlCoinsKeyimage[coin]), common.Base58Version))
				}
			}
			acc.lock.RUnlock()
			acc.isReady = false
			for token, keyimages := range keyimagesToCheck {
				result, err := rpcnode.API_HasSerialNumbers(acc.Account.PAstr, keyimages, token)
				if err != nil {
					fmt.Println(err)
					continue
				}
				coinRemain := []string{}
				coinUsed := []string{}
				acc.lock.Lock()
				for idx, used := range result {
					if used {
						coinUsed = append(coinUsed, acc.AvailableCoins[token][idx])
					}
					if !used {
						coinRemain = append(coinRemain, acc.AvailableCoins[token][idx])
					}
				}
				acc.AvailableCoins[token] = coinRemain
				if err := updateUsedKeyImages(acc.Account.PAstr, token, coinUsed); err != nil {
					panic(err)
				}
				for _, coin := range coinUsed {
					delete(acc.AvlCoinsKeyimage, coin)
					delete(acc.CoinsValue, coin)
				}
				acc.Balance[token] = 0
				for _, coin := range acc.AvailableCoins[token] {
					acc.Balance[token] += acc.CoinsValue[coin]
				}
				acc.lock.Unlock()
			}
			acc.isReady = true
			continue
		case <-acc.CTerminate:
			return
		}
	}
}
