package main

import (
	"errors"

	"github.com/incognitochain/incognito-chain/common"
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

func EncryptCoinV2() {

}

// NewCoinV2ArrayFromPaymentInfoArray
func GenCoinCommitment() {

}
func GenCoinOTA() {

}

///////////////////////

func GenAssetTag() {

}

func concealInOutputCoins(inputCoins []*coin.CoinV2, outputCoins []*coin.CoinV2) error {
	return nil
}
