package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/incognitokey"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/privacy/coin"
	"github.com/incognitochain/incognito-chain/privacy/key"
	"github.com/incognitochain/incognito-chain/privacy/operation"
	"github.com/incognitochain/incognito-chain/rpcserver/jsonresult"
	"github.com/incognitochain/incognito-chain/transaction"
	"github.com/incognitochain/incognito-chain/wallet"
)

type CoinData struct {
	coin              *coin.CoinV2
	CoinHex           string
	KeyImageEncrypted []byte
	KeyImageDecrypted []byte
}

func DecryptCoinsV2(coinList []*CoinData, viewKey key.ViewingKey, OTAKey key.OTAKey) error {
	for _, c := range coinList {
		txConcealRandomPoint, err := c.coin.GetTxRandom().GetTxConcealRandomPoint()
		if err != nil {
			return err
		}
		rK := new(operation.Point).ScalarMult(txConcealRandomPoint, viewKey.GetPrivateView())

		// Hash multiple times
		hash := operation.HashToScalar(rK.ToBytesS())
		hash = operation.HashToScalar(hash.ToBytesS())
		randomness := c.coin.GetRandomness().Sub(c.coin.GetRandomness(), hash)

		// Hash 1 more time to get value
		hash = operation.HashToScalar(hash.ToBytesS())
		value := c.coin.GetAmount().Sub(c.coin.GetAmount(), hash)

		commitment := operation.PedCom.CommitAtIndex(value, randomness, operation.PedersenValueIndex)
		// for `confidential asset` coin, we commit differently
		if c.coin.GetAssetTag() != nil {
			com, err := coin.ComputeCommitmentCA(c.coin.GetAssetTag(), randomness, value)
			if err != nil {
				err := errors.New("Cannot recompute commitment when decrypting")
				return err
			}
			commitment = com
		}
		if !operation.IsPointEqual(commitment, c.coin.GetCommitment()) {
			err := errors.New("Cannot Decrypt CoinV2: Commitment is not the same after decrypt")
			return err
		}
		c.coin.SetRandomness(randomness)
		c.coin.SetAmount(value)
	}
	if err := GetKeyImageOfCoins(coinList, OTAKey); err != nil {
		return err
	}
	return nil
}

func GetKeyImageOfCoins(coinList []*CoinData, OTAKey key.OTAKey) error {
	for _, c := range coinList {
		_, txRandomOTAPoint, index, err := c.coin.GetTxRandomDetail()
		if err != nil {
			return err
		}
		rK := new(operation.Point).ScalarMult(txRandomOTAPoint, OTAKey.GetOTASecretKey())  //(r_ota*G) * k = r_ota * K
		H := operation.HashToScalar(append(rK.ToBytesS(), common.Uint32ToBytes(index)...)) // Hash(r_ota*K, index)
		HBytes := H.ToBytesS()
		PubkeyBytes := c.coin.GetPublicKey().ToBytesS()
		c.KeyImageEncrypted = append(c.KeyImageEncrypted, HBytes...)
		c.KeyImageEncrypted = append(c.KeyImageEncrypted, PubkeyBytes...)
	}
	return nil
}

func NewCoinUniqueOTABasedOnPaymentInfo(paymentInfo *privacy.PaymentInfo, tokenID *common.Hash) (*privacy.CoinV2, error) {
	c, err := privacy.NewCoinFromPaymentInfo(paymentInfo)
	if err != nil {
		return nil, err
	}
	return c, nil // No need to check db
}

func NewCoinV2ArrayFromPaymentInfoArray(paymentInfo []*privacy.PaymentInfo, tokenID *common.Hash) ([]*privacy.CoinV2, error) {
	outputCoins := make([]*privacy.CoinV2, len(paymentInfo))
	for index, info := range paymentInfo {
		var err error
		outputCoins[index], err = NewCoinUniqueOTABasedOnPaymentInfo(info, tokenID)
		if err != nil {
			return nil, err
		}
	}
	return outputCoins, nil
}

func ExtractCoinEncryptKeyImgData(coins []coin.PlainCoin, OTAKey *key.OTAKey) (map[string]string, error) {
	result := make(map[string]string)
	for _, c := range coins {
		if c.GetVersion() != 2 {
			panic("oops")
		}
		cv2 := c.(*coin.CoinV2)
		_, txRandomOTAPoint, index, err := cv2.GetTxRandomDetail()
		if err != nil {
			return nil, err
		}
		rK := new(operation.Point).ScalarMult(txRandomOTAPoint, OTAKey.GetOTASecretKey())  //(r_ota*G) * k = r_ota * K
		H := operation.HashToScalar(append(rK.ToBytesS(), common.Uint32ToBytes(index)...)) // Hash(r_ota*K, index)
		HBytes := H.ToBytesS()
		PubkeyBytes := c.GetPublicKey().ToBytesS()
		result[hex.EncodeToString(PubkeyBytes)] = hex.EncodeToString(HBytes)
	}
	return result, nil
}

func ExtractCoinH(coins []coin.PlainCoin, OTAKey key.PrivateOTAKey) ([][]byte, error) {
	var result [][]byte
	for _, c := range coins {
		if c.GetVersion() != 2 {
			panic("oops")
		}
		cv2 := c.(*coin.CoinV2)
		_, txRandomOTAPoint, index, err := cv2.GetTxRandomDetail()
		if err != nil {
			return nil, err
		}

		otaSecret := new(operation.Scalar).FromBytesS(OTAKey)
		rK := new(operation.Point).ScalarMult(txRandomOTAPoint, otaSecret)                 //(r_ota*G) * k = r_ota * K
		H := operation.HashToScalar(append(rK.ToBytesS(), common.Uint32ToBytes(index)...)) // Hash(r_ota*K, index)
		HBytes := H.ToBytesS()
		result = append(result, HBytes)
	}
	return result, nil
}

func GetCoinsByPaymentAddress(account *Account, tokenID *common.Hash) ([]privacy.PlainCoin, map[string]*big.Int, error) {
	var outcoinList []privacy.PlainCoin
	var coinIndices map[string]*big.Int

	var keySet incognitokey.KeySet
	keySet.ReadonlyKey = account.Viewkey
	var err error
	switch NODEMODE {
	case MODERPC:
		coinIndices = make(map[string]*big.Int)
		coinList, e := rpcnode.API_ListOutputCoins(account.PAstr, "", serializeOTAKey(account), tokenID.String(), account.BeaconHeight)
		if e != nil {
			return nil, nil, e
		}
		fmt.Println("len(coinList)", tokenID.String(), coinList.Outputs)
		for _, out := range coinList.Outputs {
			for _, c := range out {
				cV2, idx, err := jsonresult.NewCoinFromJsonOutCoin(c)
				if err != nil {
					panic(err)
				}

				cv2 := cV2.(*coin.CoinV2)
				result, err := cv2.Decrypt(&keySet)
				if err != nil {
					return nil, nil, err
				}
				outcoinList = append(outcoinList, result)
				key := hex.EncodeToString(result.GetPublicKey().ToBytesS())
				coinIndices[key] = idx
			}
		}
	case MODELIGHT, MODESIM:
		wl, e := wallet.Base58CheckDeserialize(account.PAstr)
		if e != nil {
			return nil, nil, e
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
	return outcoinList, coinIndices, err
}

//----------------------------------------
//FUNCTIONS USED FOR CREATING TX
//
func chooseCoinsToSpendForAccount(accountState *AccountState, tokenID string, paymentInfos []*privacy.PaymentInfo, metadataParam metadata.Metadata, privacyCustomTokenParams *transaction.TokenParam) ([]coin.PlainCoin, uint64, error) {
	// estimate fee according to 8 recent block
	shardIDSender := accountState.Account.ShardID
	// calculate total amount to send
	totalAmmount := uint64(0)
	for _, receiver := range paymentInfos {
		totalAmmount += receiver.Amount
	}
	// get list outputcoins tx
	if tokenID == "" {
		prvCoinID := &common.Hash{}
		prvCoinID.SetBytes(common.PRVCoinID[:])
		tokenID = prvCoinID.String()
	}
	accountState.lock.RLock()
	defer accountState.lock.RUnlock()
	if _, ok := accountState.coinState.AvailableCoins[tokenID]; !ok {
		return nil, 0, errors.New("not enough token coins")
	}
	coinsPubkey := append([]string{}, accountState.coinState.AvailableCoins[tokenID]...)
	plainCoins, err := getCoinsByCoinPubkey(accountState.Account.PAstr, tokenID, coinsPubkey)
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
		kmHex := accountState.coinState.AvlCoinsKeyimage[hex.EncodeToString(coin.GetPublicKey().ToBytesS())]
		kmBytes, _ := hex.DecodeString(kmHex)
		kmPoint := operation.Point{}
		_, err := kmPoint.FromBytesS(kmBytes)
		if err != nil {
			panic(err)
		}
		coin.SetKeyImage(&kmPoint)
	}
	// check real fee(nano PRV) per tx

	beaconState, err := rpcnode.API_GetBeaconBestState()
	if err != nil {
		return nil, 0, err
	}
	beaconHeight := beaconState.BeaconHeight
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
	estimateFeeCoinPerKb := estimateFeeResult.EstimateFeeCoinPerKb
	estimateTxSizeInKb := estimateFeeResult.EstimateTxSizeInKb

	limitFee := uint64(1)
	//we default to ver 2
	estimateTxSizeInKb = transaction.EstimateTxSize(transaction.NewEstimateTxSizeParam(2, len(candidatePlainCoins), len(paymentInfos), hasPrivacy, metadata, privacyCustomTokenParams, limitFee))
	realFee := uint64(estimateFeeCoinPerKb) * uint64(estimateTxSizeInKb)
	return realFee, estimateFeeCoinPerKb, estimateTxSizeInKb, nil
}

//
//FUNCTIONS USED FOR CREATING TX
//----------------------------------------
