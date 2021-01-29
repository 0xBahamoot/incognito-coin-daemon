package main

import (
	"math/big"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/dataaccessobject/statedb"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/privacy/privacy_v2/mlsag"
	"github.com/incognitochain/incognito-chain/transaction/tx_generic"
	"github.com/incognitochain/incognito-chain/transaction/utils"
)

func generateMlsagRingWithIndexes(inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, params *tx_generic.TxPrivacyInitParams, pi int, shardID byte, ringSize int) (*mlsag.Ring, [][]*big.Int, *privacy.Point, error) {
	lenOTA, err := statedb.GetOTACoinLength(params.StateDB, *params.TokenID, shardID)
	if err != nil || lenOTA == nil {
		utils.Logger.Log.Errorf("Getting length of commitment error, either database length ota is empty or has error, error = %v", err)
		return nil, nil, nil, err
	}
	outputCoinsAsGeneric := make([]privacy.Coin, len(outputCoins))
	for i := 0; i < len(outputCoins); i++ {
		outputCoinsAsGeneric[i] = outputCoins[i]
	}
	sumOutputsWithFee := tx_generic.CalculateSumOutputsWithFee(outputCoinsAsGeneric, params.Fee)
	indexes := make([][]*big.Int, ringSize)
	ring := make([][]*privacy.Point, ringSize)
	var commitmentToZero *privacy.Point
	for i := 0; i < ringSize; i += 1 {
		sumInputs := new(privacy.Point).Identity()
		sumInputs.Sub(sumInputs, sumOutputsWithFee)

		row := make([]*privacy.Point, len(inputCoins))
		rowIndexes := make([]*big.Int, len(inputCoins))
		if i == pi {
			for j := 0; j < len(inputCoins); j += 1 {
				row[j] = inputCoins[j].GetPublicKey()
				publicKeyBytes := inputCoins[j].GetPublicKey().ToBytesS()
				if rowIndexes[j], err = statedb.GetOTACoinIndex(params.StateDB, *params.TokenID, publicKeyBytes); err != nil {
					utils.Logger.Log.Errorf("Getting commitment index error %v ", err)
					return nil, nil, nil, err
				}
				sumInputs.Add(sumInputs, inputCoins[j].GetCommitment())
			}
		} else {
			for j := 0; j < len(inputCoins); j += 1 {
				rowIndexes[j], _ = common.RandBigIntMaxRange(lenOTA)
				coinBytes, err := statedb.GetOTACoinByIndex(params.StateDB, *params.TokenID, rowIndexes[j].Uint64(), shardID)
				if err != nil {
					utils.Logger.Log.Errorf("Get coinv2 by index error %v ", err)
					return nil, nil, nil, err
				}
				coinDB := new(privacy.CoinV2)
				if err := coinDB.SetBytes(coinBytes); err != nil {
					utils.Logger.Log.Errorf("Cannot parse coinv2 byte error %v ", err)
					return nil, nil, nil, err
				}
				row[j] = coinDB.GetPublicKey()
				sumInputs.Add(sumInputs, coinDB.GetCommitment())
			}
		}
		row = append(row, sumInputs)
		if i == pi {
			commitmentToZero = sumInputs
		}
		ring[i] = row
		indexes[i] = rowIndexes
	}
	return mlsag.NewRing(ring), indexes, commitmentToZero, nil
}

func getMLSAGSigFromTxSigAndKeyImages(txSig []byte, keyImages []*privacy.Point) (*mlsag.MlsagSig, error) {
	mlsagSig, err := new(mlsag.MlsagSig).FromBytes(txSig)
	if err != nil {
		utils.Logger.Log.Errorf("Has error when converting byte to mlsag signature, err: %v", err)
		return nil, err
	}

	return mlsag.NewMlsagSig(mlsagSig.GetC(), keyImages, mlsagSig.GetR())
}
