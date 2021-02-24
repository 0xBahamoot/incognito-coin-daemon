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
	BeaconHeight   uint64
}

type AccountState struct {
	Account *Account
	Balance map[string]uint64
	// AvailableBalance map[string]uint64
	// isReady bool

	lock sync.RWMutex
	// PendingCoins []string //wait for tx to confirm
	//map[tokenID][]coinpubkey
	// AvailableCoins   map[string][]string //avaliable to use
	// EncryptedCoins   map[string][]string //encrypted, dont know whether been used
	// AvlCoinsKeyimage map[string]string
	// CoinsValue       map[string]uint64

	coinState  AccountCoinState
	CTerminate chan struct{}
}

type AccountCoinState struct {
	AvailableCoins   map[string][]string //avaliable to use
	EncryptedCoins   map[string][]string //encrypted, dont know whether been used
	AvlCoinsKeyimage map[string]string
	CoinsValue       map[string]uint64
}

var accountListLck sync.RWMutex
var accountList map[string]*AccountState
var currentAccount string

func (as *AccountState) init() {
	// as.isReady = false
	as.Balance = make(map[string]uint64)
	// as.AvailableBalance = make(map[string]uint64)
	as.coinState.AvailableCoins = make(map[string][]string)
	as.coinState.EncryptedCoins = make(map[string][]string)
	as.coinState.AvlCoinsKeyimage = make(map[string]string)
	as.coinState.CoinsValue = make(map[string]uint64)
	as.CTerminate = make(chan struct{})
}

func importAccount(name string, paymentAddr string, viewKey string, OTAKey string, beaconHeight uint64) error {
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
	acc.BeaconHeight = beaconHeight
	accState.Account = acc
	accountList[name] = accState

	if err := saveAccount(name, acc); err != nil {
		return err
	}

	go accState.WatchBalance()
	fmt.Printf("import account %v success\n", name)
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
		acc.Viewkey.Pk = wl.KeySet.PaymentAddress.Pk
		accState.Account = acc
		if err := accState.loadCoinState(); err != nil {
			panic(err)
		}

		go accState.WatchBalance()
		accountList[accName] = accState
	}
	accountListLck.Unlock()
	go scanForNewCoins()
	return nil
}

func scanForNewCoins() {
	for {
		if len(accountList) == 0 || rpcnode == nil {
			time.Sleep(10 * time.Second)
			continue
		}
		accountListLck.RLock()
		////////////////////////////////////
		// add more token

		var wg sync.WaitGroup
		var tokenIDs []string
		tokenIDs = append(tokenIDs, common.PRVCoinID.String())
		tokensInfo, err := rpcnode.API_ListPrivacyCustomToken()
		if err != nil {
			panic(err)
		}
		for _, tokenInfo := range tokensInfo.ListCustomToken {
			tokenIDs = append(tokenIDs, tokenInfo.ID)
		}
		for name, account := range accountList {
			wg.Add(1)
			go func(n string, a *AccountState) {
				defer wg.Done()
				fmt.Printf("scan coins for account %s\n", n)
				var wg2 sync.WaitGroup
				for _, tokenID := range tokenIDs {
					wg2.Add(1)
					go func(tID string) {
						defer wg2.Done()
						tokenIDHash, _ := common.Hash{}.NewHashFromStr(tID)
						coinList, err := GetCoinsByPaymentAddress(a.Account, tokenIDHash)
						if err != nil {
							fmt.Println(err)
							return
						}
						if len(coinList) > 0 {
							coins, err := checkCoinExistAndSave(a.Account.PAstr, tID, coinList)
							if err != nil {
								panic(err)
							}

							a.lock.Lock()
							a.coinState.EncryptedCoins[tID] = append(a.coinState.EncryptedCoins[tID], coins...)
							for _, coin := range coinList {
								key := hex.EncodeToString(coin.GetPublicKey().ToBytesS())
								a.coinState.CoinsValue[key] = coin.GetValue()
								fmt.Println("a.CoinsValue[key]", coin.GetValue())
							}
							fmt.Println(len(a.coinState.EncryptedCoins[tID]), "of ", tID, "need decrypt")
							a.lock.Unlock()
						}
					}(tokenID)
				}
				wg2.Wait()
				a.lock.Lock()
				// a.isReady = false
				a.saveCoinStateAndUnlock()
				// a.isReady = true
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
		result[name] = account.GetBalance()
	}
	accountListLck.RUnlock()
	return result
}

func (acc *AccountState) GetBalance() map[string]uint64 {
	acc.lock.RLock()
	result := make(map[string]uint64)
	for token, balance := range acc.Balance {
		result[token] = balance
	}
	acc.lock.RUnlock()
	return result
}

func (acc *AccountState) UpdateDecryptedCoin(coinList map[string][]string, keyimages map[string]string) error {
	acc.lock.Lock()
	// acc.isReady = false
	for token, coins := range coinList {
		newCoinList := []string{}
		tokenkms := make(map[string]string)
		for _, encoin := range acc.coinState.EncryptedCoins[token] {
			stillEncrypted := true
			for _, decoin := range coins {
				if decoin == encoin {
					stillEncrypted = false
					tokenkms[decoin] = keyimages[decoin]
					acc.coinState.AvailableCoins[token] = append(acc.coinState.AvailableCoins[token], decoin)
					break
				}
			}
			if stillEncrypted {
				newCoinList = append(newCoinList, encoin)
			}
		}
		acc.coinState.EncryptedCoins[token] = newCoinList
		if err := saveKeyImages(tokenkms, token, acc.Account.PAstr); err != nil {
			panic(err)
		}
	}
	for k, v := range keyimages {
		acc.coinState.AvlCoinsKeyimage[k] = v
	}

	acc.saveCoinStateAndUnlock()
	// acc.isReady = true
	return nil
}

func (acc *AccountState) WatchBalance() {
	for {
		if rpcnode == nil {
			continue
		}
		break
	}

	tc := time.NewTicker(defaultBalanceWatchInterval)
	otaKeyset := []byte{}
	otaKeyset = append(otaKeyset, acc.Account.OTAKey...)
	otaKeyset = append(otaKeyset, acc.Account.PaymentAddress.OTAPublic...)
	otakeyStr := hex.EncodeToString(otaKeyset)
	_, err := rpcnode.API_SubmitKey(otakeyStr)
	if err != nil {
		panic(err)
	}
	for {
		select {
		case <-tc.C:
			if len(acc.coinState.AvailableCoins) == 0 {
				continue
			}
			acc.lock.RLock()
			keyimagesToCheck := make(map[string][]string)
			for token, coins := range acc.coinState.AvailableCoins {
				for _, coin := range coins {
					kmb, err := hex.DecodeString(acc.coinState.AvlCoinsKeyimage[coin])
					if err != nil {
						panic(err)
					}
					keyimagesToCheck[token] = append(keyimagesToCheck[token], base58.Base58Check{}.Encode(kmb, common.Base58Version))
				}
			}

			acc.lock.RUnlock()
			// acc.isReady = false
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
						coinUsed = append(coinUsed, acc.coinState.AvailableCoins[token][idx])
					} else {
						coinRemain = append(coinRemain, acc.coinState.AvailableCoins[token][idx])
					}
				}
				acc.coinState.AvailableCoins[token] = coinRemain
				if err := updateUsedKeyImages(acc.Account.PAstr, token, coinUsed); err != nil {
					panic(err)
				}
				for _, coin := range coinUsed {
					delete(acc.coinState.AvlCoinsKeyimage, coin)
					delete(acc.coinState.CoinsValue, coin)
				}
				newBalance := uint64(0)
				for _, coin := range acc.coinState.AvailableCoins[token] {
					newBalance += acc.coinState.CoinsValue[coin]
					fmt.Println("acc.CoinsValue", acc.coinState.CoinsValue[coin])
				}
				if acc.Balance[token] != newBalance {
					acc.Balance[token] = newBalance
					fmt.Println("newBalance", newBalance, len((acc.coinState.CoinsValue)))
				}
				acc.saveCoinStateAndUnlock()
			}
			// acc.isReady = true
			continue
		case <-acc.CTerminate:
			return
		}
	}
}

func serializeOTAKey(account *Account) string {
	keyBytes := make([]byte, 0)
	keyBytes = append(keyBytes, wallet.OTAKeyType)
	keyBytes = append(keyBytes, byte(len(account.PaymentAddress.Pk))) // set length publicSpend
	keyBytes = append(keyBytes, account.PaymentAddress.Pk[:]...)      // set publicSpend

	keyBytes = append(keyBytes, byte(len(account.OTAKey))) // set length OTASecretKey
	keyBytes = append(keyBytes, account.OTAKey[:]...)      // set OTASecretKey

	checkSum := base58.ChecksumFirst4Bytes(keyBytes, true)

	serializedKey := append(keyBytes, checkSum...)
	return base58.Base58Check{}.NewEncode(serializedKey, common.ZeroByte)
}

func serializeViewKey(account *Account) string {
	keyBytes := make([]byte, 0)
	keyBytes = append(keyBytes, wallet.ReadonlyKeyType)

	keyBytes = append(keyBytes, byte(len(account.Viewkey.Pk))) // set length PaymentAddress
	keyBytes = append(keyBytes, account.Viewkey.Pk[:]...)      // set PaymentAddress

	keyBytes = append(keyBytes, byte(len(account.Viewkey.Rk))) // set length Skenc
	keyBytes = append(keyBytes, account.Viewkey.Rk[:]...)      // set Pkenc
	checkSum := base58.ChecksumFirst4Bytes(keyBytes, true)

	serializedKey := append(keyBytes, checkSum...)
	return base58.Base58Check{}.NewEncode(serializedKey, common.ZeroByte)
}

func (acc *AccountState) saveCoinStateAndUnlock() {
	defer acc.lock.Unlock()
	err := saveAccountCoinState(acc.Account.PAstr, acc.coinState)
	if err != nil {
		panic(err)
	}
	fmt.Println("save coinState success")
	return
}
func (acc *AccountState) loadCoinState() error {
	acc.lock.Lock()
	coinState, err := loadAccountCoinState(acc.Account.PAstr)
	if err != nil {
		panic(err)
	}
	acc.coinState = *coinState
	acc.lock.Unlock()
	return nil
}
