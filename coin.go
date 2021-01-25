package main

import (
	"encoding/hex"
	"errors"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/privacy/coin"
	"github.com/incognitochain/incognito-chain/privacy/key"
	"github.com/incognitochain/incognito-chain/privacy/operation"
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

func ExtractCoinEncryptKeyImgData(coins []coin.PlainCoin, OTAKey *key.OTAKey) (map[string][]byte, error) {
	result := make(map[string][]byte)
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
		data := []byte{}
		data = append(data, HBytes...)
		result[hex.EncodeToString(PubkeyBytes)] = data
	}
	return result, nil
}
