package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"github.com/0xkumi/incognito-dev-framework/rpcclient"
	"github.com/incognitochain/incognito-chain/blockchain"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/dataaccessobject/statedb"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/multiview"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/privacy/coin"
	"github.com/incognitochain/incognito-chain/privacy/operation"
	"github.com/incognitochain/incognito-chain/rpcserver/jsonresult"
	"github.com/incognitochain/incognito-chain/transaction"
	"github.com/incognitochain/incognito-chain/wallet"
	"github.com/syndtr/goleveldb/leveldb"
)

var localnode interface {
	GetUserDatabase() *leveldb.DB
	GetBlockchain() *blockchain.BlockChain
	OnNewBlockFromParticularHeight(chainID int, blkHeight int64, isFinalized bool, f func(bc *blockchain.BlockChain, h common.Hash, height uint64))
}
var rpcnode *rpcclient.RPCClient

var stateLock sync.Mutex
var ShardProcessedState map[byte]uint64
var TransactionStateDB map[byte]*statedb.StateDB

func OnNewShardBlock(bc *blockchain.BlockChain, h common.Hash, height uint64) {
	var blk blockchain.ShardBlock
	blkBytes, err := localnode.GetUserDatabase().Get(h.Bytes(), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := json.Unmarshal(blkBytes, &blk); err != nil {
		fmt.Println(err)
		return
	}

	transactionStateDB := TransactionStateDB[byte(blk.GetShardID())]

	if len(blk.Body.Transactions) > 0 {
		err = bc.CreateAndSaveTxViewPointFromBlock(&blk, transactionStateDB)
		if err != nil {
			panic(err)
		}
	}

	transactionRootHash, err := transactionStateDB.Commit(true)
	if err != nil {
		panic(err)
	}
	err = transactionStateDB.Database().TrieDB().Commit(transactionRootHash, false)
	if err != nil {
		panic(err)
	}
	bc.GetBestStateShard(byte(blk.GetShardID())).TransactionStateDBRootHash = transactionRootHash
	batchData := bc.GetShardChainDatabase(blk.Header.ShardID).NewBatch()
	err = bc.BackupShardViews(batchData, blk.Header.ShardID)
	if err != nil {
		panic("Backup shard view error")
	}

	if err := batchData.Write(); err != nil {
		panic(err)
	}
	statePrefix := fmt.Sprintf("coin-processed-%v", blk.Header.ShardID)
	err = localnode.GetUserDatabase().Put([]byte(statePrefix), []byte(fmt.Sprintf("%v", blk.Header.Height)), nil)
	if err != nil {
		panic(err)
	}
	stateLock.Lock()
	ShardProcessedState[blk.Header.ShardID] = blk.Header.Height
	stateLock.Unlock()
	if (blk.Header.Height % 100) == 0 {
		shardID := blk.Header.ShardID
		localnode.GetBlockchain().ShardChain[shardID] = blockchain.NewShardChain(int(shardID), multiview.NewMultiView(), localnode.GetBlockchain().GetConfig().BlockGen, localnode.GetBlockchain(), common.GetShardChainKey(shardID))
		if err := localnode.GetBlockchain().RestoreShardViews(shardID); err != nil {
			panic(err)
		}
		stateLock.Lock()
		TransactionStateDB[byte(blk.GetShardID())] = localnode.GetBlockchain().GetBestStateShard(blk.Header.ShardID).GetCopiedTransactionStateDB()
		stateLock.Unlock()
	}
}

func GetCoinsByPaymentAddress(account *Account, tokenID *common.Hash) ([]privacy.PlainCoin, error) {
	var outcoinList []privacy.PlainCoin
	if tokenID == nil {
		tokenID = &common.Hash{}
		tokenID.SetBytes(common.PRVCoinID[:])
	}
	var err error
	switch NODEMODE {
	case MODERPC:
		coinList, e := rpcnode.API_ListOutputCoins(account.PAstr, tokenID.String())
		if e != nil {
			return nil, e
		}
		for _, out := range coinList.Outputs {
			for _, c := range out {
				cV2, idx, err := jsonresult.NewCoinFromJsonOutCoin(c)
				_ = idx
				if err != nil {
					panic(err)
				}
				cv2 := cV2.(*coin.CoinV2)
				outcoinList = append(outcoinList, cv2)
			}
		}
	case MODELIGHT, MODESIM:
		wl, e := wallet.Base58CheckDeserialize(account.PAstr)
		if e != nil {
			return nil, e
		}
		lastByte := wl.KeySet.PaymentAddress.Pk[len(wl.KeySet.PaymentAddress.Pk)-1]
		shardIDSender := common.GetShardIDFromLastByte(lastByte)
		wl.KeySet.OTAKey.SetPublicSpend(wl.KeySet.PaymentAddress.Pk)
		wl.KeySet.OTAKey.SetOTASecretKey(account.OTAKey)
		wl.KeySet.ReadonlyKey.Pk = wl.KeySet.PaymentAddress.Pk
		wl.KeySet.ReadonlyKey.Rk = append(wl.KeySet.ReadonlyKey.Rk, account.Viewkey.Rk...)
		coinList, _, _, _ := localnode.GetBlockchain().GetListDecryptedOutputCoinsVer2ByKeyset(&wl.KeySet, shardIDSender, tokenID, 0)
		outcoinList = append(outcoinList, coinList...)
	}
	return outcoinList, err
}

func initCoinService() {
	ShardProcessedState = make(map[byte]uint64)
	TransactionStateDB = make(map[byte]*statedb.StateDB)
	//load ShardProcessedState
	for i := 0; i < localnode.GetBlockchain().GetChainParams().ActiveShards; i++ {
		statePrefix := fmt.Sprintf("coin-processed-%v", i)
		v, err := localnode.GetUserDatabase().Get([]byte(statePrefix), nil)
		if err != nil {
			fmt.Println(err)
		}
		if v != nil {
			height, err := strconv.ParseUint(string(v), 0, 64)
			if err != nil {
				fmt.Println(err)
				continue
			}
			ShardProcessedState[byte(i)] = height
		} else {
			ShardProcessedState[byte(i)] = 1
		}
		TransactionStateDB[byte(i)] = localnode.GetBlockchain().GetBestStateShard(byte(i)).GetCopiedTransactionStateDB()
		fmt.Println("TransactionStateDB[byte(i)]", byte(i), TransactionStateDB[byte(i)])
	}
	for i := 0; i < localnode.GetBlockchain().GetChainParams().ActiveShards; i++ {
		localnode.OnNewBlockFromParticularHeight(i, int64(ShardProcessedState[byte(i)]), true, OnNewShardBlock)
	}
}

//----------------------------------------
//FUNCTIONS USED FOR CREATING TX
//
func chooseCoinsForAccount(accountState *AccountState, paymentInfos []*privacy.PaymentInfo, metadataParam metadata.Metadata, privacyCustomTokenParams *transaction.TokenParam) ([]coin.PlainCoin, uint64, error) {
	// estimate fee according to 8 recent block
	shardIDSender := accountState.Account.ShardID
	// calculate total amount to send
	totalAmmount := uint64(0)
	for _, receiver := range paymentInfos {
		totalAmmount += receiver.Amount
	}
	// get list outputcoins tx
	prvCoinID := &common.Hash{}
	prvCoinID.SetBytes(common.PRVCoinID[:])
	accountState.lock.RLock()
	defer accountState.lock.RUnlock()
	coinsPubkey := append([]string{}, accountState.AvailableCoins[prvCoinID.String()]...)
	plainCoins, err := getCoinsByCoinPubkey(accountState.Account.PAstr, prvCoinID.String(), coinsPubkey)
	if err != nil {
		return nil, 0, err
	}
	if len(plainCoins) == 0 && totalAmmount > 0 {
		return nil, 0, errors.New("not enough output coin")
	}

	// Use Knapsack to get candiate output coin
	candidatePlainCoins, outCoins, candidateOutputCoinAmount, err := chooseBestOutCoinsToSpent(plainCoins, totalAmmount)
	if err != nil {
		return nil, 0, err
	}
	// refund out put for sender
	overBalanceAmount := candidateOutputCoinAmount - totalAmmount
	if overBalanceAmount > 0 {
		// add more into output for estimate fee
		paymentInfos = append(paymentInfos, &privacy.PaymentInfo{
			PaymentAddress: accountState.Account.PaymentAddress,
			Amount:         overBalanceAmount,
		})
	}
	for _, coin := range candidatePlainCoins {
		kmHex := accountState.AvlCoinsKeyimage[hex.EncodeToString(coin.GetPublicKey().ToBytesS())]
		kmBytes, _ := hex.DecodeString(kmHex)
		kmPoint := operation.Point{}
		kmPoint.FromBytesS(kmBytes)
		coin.SetKeyImage(&kmPoint)
	}
	// check real fee(nano PRV) per tx

	// beaconState, err := rpcnode.API_GetBeaconBestState()
	// if err != nil {
	// 	return nil, 0, err
	// }
	beaconHeight := localnode.GetBlockchain().GetBeaconBestState().BeaconHeight
	// ver, err := transaction.GetTxVersionFromCoins(candidatePlainCoins)
	realFee, _, _, err := estimateFee(accountState.Account.PAstr, false, candidatePlainCoins,
		paymentInfos, shardIDSender, true,
		metadataParam,
		privacyCustomTokenParams, int64(beaconHeight))
	if err != nil {
		return nil, 0, err
	}
	if totalAmmount == 0 && realFee == 0 {
		if metadataParam != nil {
			metadataType := metadataParam.GetType()
			switch metadataType {
			case metadata.WithDrawRewardRequestMeta:
				{
					return nil, realFee, nil
				}
			}
			return nil, realFee, fmt.Errorf("totalAmmount: %+v, realFee: %+v", totalAmmount, realFee)
		}
		if privacyCustomTokenParams != nil {
			// for privacy token
			return nil, 0, nil
		}
	}
	needToPayFee := int64((totalAmmount + realFee) - candidateOutputCoinAmount)
	// if not enough to pay fee
	if needToPayFee > 0 {
		if len(outCoins) > 0 {
			candidateOutputCoinsForFee, _, _, err := chooseBestOutCoinsToSpent(outCoins, uint64(needToPayFee))
			if err != nil {
				return nil, 0, err
			}
			candidatePlainCoins = append(candidatePlainCoins, candidateOutputCoinsForFee...)
		}
	}
	return candidatePlainCoins, realFee, nil
}

func chooseBestOutCoinsToSpent(outCoins []coin.PlainCoin, amount uint64) (resultOutputCoins []coin.PlainCoin, remainOutputCoins []coin.PlainCoin, totalResultOutputCoinAmount uint64, err error) {
	resultOutputCoins = make([]coin.PlainCoin, 0)
	remainOutputCoins = make([]coin.PlainCoin, 0)
	totalResultOutputCoinAmount = uint64(0)

	// either take the smallest coins, or a single largest one
	var outCoinOverLimit coin.PlainCoin
	outCoinsUnderLimit := make([]coin.PlainCoin, 0)
	for _, outCoin := range outCoins {
		if outCoin.GetValue() < amount {
			outCoinsUnderLimit = append(outCoinsUnderLimit, outCoin)
		} else if outCoinOverLimit == nil {
			outCoinOverLimit = outCoin
		} else if outCoinOverLimit.GetValue() > outCoin.GetValue() {
			remainOutputCoins = append(remainOutputCoins, outCoin)
		} else {
			remainOutputCoins = append(remainOutputCoins, outCoinOverLimit)
			outCoinOverLimit = outCoin
		}
	}
	sort.Slice(outCoinsUnderLimit, func(i, j int) bool {
		return outCoinsUnderLimit[i].GetValue() < outCoinsUnderLimit[j].GetValue()
	})
	for _, outCoin := range outCoinsUnderLimit {
		if totalResultOutputCoinAmount < amount {
			totalResultOutputCoinAmount += outCoin.GetValue()
			resultOutputCoins = append(resultOutputCoins, outCoin)
		} else {
			remainOutputCoins = append(remainOutputCoins, outCoin)
		}
	}
	if outCoinOverLimit != nil && (outCoinOverLimit.GetValue() > 2*amount || totalResultOutputCoinAmount < amount) {
		remainOutputCoins = append(remainOutputCoins, resultOutputCoins...)
		resultOutputCoins = []coin.PlainCoin{outCoinOverLimit}
		totalResultOutputCoinAmount = outCoinOverLimit.GetValue()
	} else if outCoinOverLimit != nil {
		remainOutputCoins = append(remainOutputCoins, outCoinOverLimit)
	}
	if totalResultOutputCoinAmount < amount {
		return resultOutputCoins, remainOutputCoins, totalResultOutputCoinAmount, errors.New("Not enough coin")
	}
	return resultOutputCoins, remainOutputCoins, totalResultOutputCoinAmount, nil
}

func estimateFee(
	paymentAddress string,
	isGetPTokenFee bool,
	candidatePlainCoins []coin.PlainCoin,
	paymentInfos []*privacy.PaymentInfo, shardID byte,
	hasPrivacy bool,
	metadata metadata.Metadata,
	privacyCustomTokenParams *transaction.TokenParam,
	beaconHeight int64) (uint64, uint64, uint64, error) {
	return 8, 8, 8, nil
	// check real fee(nano PRV) per tx
	var realFee uint64
	estimateFeeCoinPerKb := uint64(0)
	estimateTxSizeInKb := uint64(0)
	// tokenID := &common.Hash{}
	tokenIDStr := ""
	if isGetPTokenFee {
		if privacyCustomTokenParams != nil {
			tokenID, _ := common.Hash{}.NewHashFromStr(privacyCustomTokenParams.PropertyID)
			tokenIDStr = tokenID.String()
		}
	}
	estimateFeeResult, err := rpcnode.API_EstimateFeeWithEstimator(paymentAddress, tokenIDStr)
	if err != nil {
		return 0, 0, 0, err
	}
	estimateFeeCoinPerKb = estimateFeeResult.EstimateFeeCoinPerKb
	estimateTxSizeInKb = estimateFeeResult.EstimateTxSizeInKb

	limitFee := uint64(1)
	//we default to ver 2
	estimateTxSizeInKb = transaction.EstimateTxSize(transaction.NewEstimateTxSizeParam(2, len(candidatePlainCoins), len(paymentInfos), hasPrivacy, metadata, privacyCustomTokenParams, limitFee))
	realFee = uint64(estimateFeeCoinPerKb) * uint64(estimateTxSizeInKb)
	return realFee, estimateFeeCoinPerKb, estimateTxSizeInKb, nil
}

//
//FUNCTIONS USED FOR CREATING TX
//----------------------------------------
