package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/dataaccessobject/statedb"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/privacy/operation"
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
	var cmtIndices []uint64
	var commitments []*privacy.Point
	var publicKeys []*privacy.Point
	// var assetTags []*privacy.Point
	if NODEMODE == MODERPC {
		cmtIndices, commitments, publicKeys, _, err = GetRandomCommitmentsAndPublicKeys(shardID, params.TokenID.String(), len(inputCoins))
		if err != nil {
			return nil, nil, nil, err
		}
	}
	currentIndex := 0
	for i := 0; i < ringSize; i++ {
		sumInputs := new(privacy.Point).Identity()
		sumInputs.Sub(sumInputs, sumOutputsWithFee)

		row := make([]*privacy.Point, len(inputCoins))
		rowIndexes := make([]*big.Int, len(inputCoins))
		if i == pi {
			for j := 0; j < len(inputCoins); j++ {
				row[j] = inputCoins[j].GetPublicKey()
				publicKeyBytes := inputCoins[j].GetPublicKey().ToBytesS()
				if NODEMODE == MODERPC {
					if rowIndexes[j], err = getCoinIndexViaCoinDB(hex.EncodeToString(inputCoins[j].GetPublicKey().ToBytesS())); err != nil {
						fmt.Errorf("Getting commitment index error %v ", err)
						return nil, nil, nil, err
					}
				} else {
					if rowIndexes[j], err = statedb.GetOTACoinIndex(params.StateDB, *params.TokenID, publicKeyBytes); err != nil {
						fmt.Errorf("Getting commitment index error %v ", err)
						return nil, nil, nil, err
					}
				}
				sumInputs.Add(sumInputs, inputCoins[j].GetCommitment())
			}
		} else {
			if NODEMODE == MODERPC {
				for j := 0; j < len(inputCoins); j++ {
					rowIndexes[j] = new(big.Int).SetUint64(cmtIndices[currentIndex])
					row[j] = publicKeys[currentIndex]
					sumInputs.Add(sumInputs, commitments[currentIndex])

					currentIndex++
				}
			} else {
				for j := 0; j < len(inputCoins); j++ {
					rowIndexes[j], _ = common.RandBigIntMaxRange(lenOTA)
					coinBytes, err := statedb.GetOTACoinByIndex(params.StateDB, *params.TokenID, rowIndexes[j].Uint64(), shardID)
					if err != nil {
						fmt.Errorf("Get coinv2 by index error %v ", err)
						return nil, nil, nil, err
					}
					coinDB := new(privacy.CoinV2)
					if err := coinDB.SetBytes(coinBytes); err != nil {
						fmt.Errorf("Cannot parse coinv2 byte error %v ", err)
						return nil, nil, nil, err
					}
					row[j] = coinDB.GetPublicKey()
					sumInputs.Add(sumInputs, coinDB.GetCommitment())
				}
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

//CA

func generateMlsagRingWithIndexesCA(inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, params *tx_generic.TxPrivacyInitParams, pi int, shardID byte, ringSize int) (*mlsag.Ring, [][]*big.Int, []*privacy.Point, error) {
	lenOTA, err := statedb.GetOTACoinLength(params.StateDB, common.ConfidentialAssetID, shardID)
	if err != nil || lenOTA == nil {
		utils.Logger.Log.Errorf("Getting length of commitment error, either database length ota is empty or has error, error = %v", err)
		return nil, nil, nil, err
	}
	outputCoinsAsGeneric := make([]privacy.Coin, len(outputCoins))
	for i := 0; i < len(outputCoins); i++ {
		outputCoinsAsGeneric[i] = outputCoins[i]
	}
	sumOutputsWithFee := tx_generic.CalculateSumOutputsWithFee(outputCoinsAsGeneric, params.Fee)
	inCount := new(privacy.Scalar).FromUint64(uint64(len(inputCoins)))
	outCount := new(privacy.Scalar).FromUint64(uint64(len(outputCoins)))

	sumOutputAssetTags := new(privacy.Point).Identity()
	for _, oc := range outputCoins {
		if oc.GetAssetTag() == nil {
			utils.Logger.Log.Errorf("CA error: missing asset tag for signing in output coin - %v", oc.Bytes())
			err := utils.NewTransactionErr(utils.SignTxError, errors.New("Cannot sign CA token : an output coin does not have asset tag"))
			return nil, nil, nil, err
		}
		sumOutputAssetTags.Add(sumOutputAssetTags, oc.GetAssetTag())
	}
	sumOutputAssetTags.ScalarMult(sumOutputAssetTags, inCount)

	indexes := make([][]*big.Int, ringSize)
	ring := make([][]*privacy.Point, ringSize)
	var lastTwoColumnsCommitmentToZero []*privacy.Point
	for i := 0; i < ringSize; i += 1 {
		sumInputs := new(privacy.Point).Identity()
		sumInputs.Sub(sumInputs, sumOutputsWithFee)
		sumInputAssetTags := new(privacy.Point).Identity()

		row := make([]*privacy.Point, len(inputCoins))
		rowIndexes := make([]*big.Int, len(inputCoins))
		if i == pi {
			for j := 0; j < len(inputCoins); j += 1 {
				row[j] = inputCoins[j].GetPublicKey()
				publicKeyBytes := inputCoins[j].GetPublicKey().ToBytesS()
				if rowIndexes[j], err = statedb.GetOTACoinIndex(params.StateDB, common.ConfidentialAssetID, publicKeyBytes); err != nil {
					utils.Logger.Log.Errorf("Getting commitment index error %v ", err)
					return nil, nil, nil, err
				}
				sumInputs.Add(sumInputs, inputCoins[j].GetCommitment())
				inputCoin_specific, ok := inputCoins[j].(*privacy.CoinV2)
				if !ok {
					return nil, nil, nil, errors.New("Cannot cast a coin as v2")
				}
				if inputCoin_specific.GetAssetTag() == nil {
					utils.Logger.Log.Errorf("CA error: missing asset tag for signing in input coin - %v", inputCoin_specific.Bytes())
					err := utils.NewTransactionErr(utils.SignTxError, errors.New("Cannot sign CA token : an input coin does not have asset tag"))
					return nil, nil, nil, err
				}
				sumInputAssetTags.Add(sumInputAssetTags, inputCoin_specific.GetAssetTag())
			}
		} else {
			for j := 0; j < len(inputCoins); j += 1 {
				rowIndexes[j], _ = common.RandBigIntMaxRange(lenOTA)
				coinBytes, err := statedb.GetOTACoinByIndex(params.StateDB, common.ConfidentialAssetID, rowIndexes[j].Uint64(), shardID)
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
				if coinDB.GetAssetTag() == nil {
					utils.Logger.Log.Errorf("CA error: missing asset tag for signing in DB coin - %v", coinBytes)
					err := utils.NewTransactionErr(utils.SignTxError, errors.New("Cannot sign CA token : a CA coin in DB does not have asset tag"))
					return nil, nil, nil, err
				}
				sumInputAssetTags.Add(sumInputAssetTags, coinDB.GetAssetTag())
			}
		}
		sumInputAssetTags.ScalarMult(sumInputAssetTags, outCount)

		assetSum := new(privacy.Point).Sub(sumInputAssetTags, sumOutputAssetTags)
		row = append(row, assetSum)
		row = append(row, sumInputs)
		if i == pi {
			utils.Logger.Log.Debugf("Last 2 columns in ring are %s and %s\n", assetSum.MarshalText(), sumInputs.MarshalText())
			lastTwoColumnsCommitmentToZero = []*privacy.Point{assetSum, sumInputs}
		}

		ring[i] = row
		indexes[i] = rowIndexes
	}
	return mlsag.NewRing(ring), indexes, lastTwoColumnsCommitmentToZero, nil
}

//prepare for mlsag
// m := len(this.privateKeys)
// n := len(this.R.keys)
func createRandomChallenges(m, n, pi int) (alpha []*operation.Scalar, r [][]*operation.Scalar) {
	// alpha = make([]*operation.Scalar, m)
	// for i := 0; i < m; i += 1 {
	// 	alpha[i] = operation.RandomScalar()
	// }
	r = make([][]*operation.Scalar, n)
	for i := 0; i < n; i += 1 {
		r[i] = make([]*operation.Scalar, m)
		if i == pi {
			continue
		}
		for j := 0; j < m; j += 1 {
			r[i][j] = operation.RandomScalar()
		}
	}
	return
}

func calculateFirstC(digest [common.HashSize]byte, alpha []*operation.Scalar, K []*operation.Point) (*operation.Scalar, error) {
	if len(alpha) != len(K) {
		return nil, errors.New("Error in MLSAG: Calculating first C must have length of alpha be the same with length of ring R")
	}
	var b []byte
	b = append(b, digest[:]...)

	// Process columns before the last
	for i := 0; i < len(K)-1; i += 1 {
		alphaG := new(operation.Point).ScalarMultBase(alpha[i])

		H := operation.HashToPoint(K[i].ToBytesS())
		alphaH := new(operation.Point).ScalarMult(H, alpha[i])

		b = append(b, alphaG.ToBytesS()...)
		b = append(b, alphaH.ToBytesS()...)
	}

	// Process last column
	alphaG := new(operation.Point).ScalarMult(
		operation.PedCom.G[operation.PedersenRandomnessIndex],
		alpha[len(K)-1],
	)
	b = append(b, alphaG.ToBytesS()...)

	return operation.HashToScalar(b), nil
}

func calculateNextC(digest [common.HashSize]byte, r []*operation.Scalar, c *operation.Scalar, K []*operation.Point, keyImages []*operation.Point) (*operation.Scalar, error) {
	if len(r) != len(K) || len(r) != len(keyImages) {
		fmt.Println("len(r) ,len(K) , len(r) ,len(keyImages)", len(r), len(K), len(r), len(keyImages))
		return nil, errors.New("Error in MLSAG: Calculating next C must have length of r be the same with length of ring R and same with length of keyImages")
	}
	var b []byte
	b = append(b, digest[:]...)

	// Below is the mathematics within the Monero paper:
	// If you are reviewing my code, please refer to paper
	// rG: r*G
	// cK: c*R
	// rG_cK: rG + cK
	//
	// HK: H_p(K_i)
	// rHK: r_i*H_p(K_i)
	// cKI: c*R~ (KI as keyImage)
	// rHK_cKI: rHK + cKI

	// Process columns before the last
	for i := 0; i < len(K)-1; i += 1 {
		rG := new(operation.Point).ScalarMultBase(r[i])
		if i == len(K)-1 {
			rG = new(operation.Point).ScalarMult(
				operation.PedCom.G[operation.PedersenRandomnessIndex],
				r[i],
			)
		}
		cK := new(operation.Point).ScalarMult(K[i], c)
		rG_cK := new(operation.Point).Add(rG, cK)

		HK := operation.HashToPoint(K[i].ToBytesS())
		rHK := new(operation.Point).ScalarMult(HK, r[i])
		cKI := new(operation.Point).ScalarMult(keyImages[i], c)
		rHK_cKI := new(operation.Point).Add(rHK, cKI)

		b = append(b, rG_cK.ToBytesS()...)
		b = append(b, rHK_cKI.ToBytesS()...)
	}

	// Process last column
	rG := new(operation.Point).ScalarMult(
		operation.PedCom.G[operation.PedersenRandomnessIndex],
		r[len(K)-1],
	)
	cK := new(operation.Point).ScalarMult(K[len(K)-1], c)
	rG_cK := new(operation.Point).Add(rG, cK)
	b = append(b, rG_cK.ToBytesS()...)

	return operation.HashToScalar(b), nil
}

func calculateC(message [common.HashSize]byte, ring *mlsag.Ring, pi int, coinsKeyImage []*operation.Point, alpha []*operation.Scalar, r [][]*operation.Scalar) ([]*operation.Scalar, error) {
	// m := len(this.privateKeys)+1 //len(coinsKeyImage)+1 ?
	R := ring.GetKeys()
	n := len(R)

	c := make([]*operation.Scalar, n)
	firstC, err := calculateFirstC(
		message,
		alpha,
		R[pi],
	)
	if err != nil {
		return nil, err
	}

	var i int = (pi + 1) % n
	c[i] = firstC
	for next := (i + 1) % n; i != pi; {
		nextC, err := calculateNextC(
			message,
			r[i], c[i],
			R[i],
			coinsKeyImage,
		)
		if err != nil {
			return nil, err
		}
		c[next] = nextC
		i = next
		next = (next + 1) % n
	}

	// TO BE CALCULATE ON LEDGER
	// for i := 0; i < m; i += 1 {
	// 	ck := new(operation.Scalar).Mul(c[this.pi], this.privateKeys[i])
	// 	r[this.pi][i] = new(operation.Scalar).Sub(alpha[i], ck)
	// }

	return c, nil
}
