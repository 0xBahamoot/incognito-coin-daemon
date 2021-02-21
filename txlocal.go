package main

import (
	"errors"
	"fmt"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/privacy/operation"
	"github.com/incognitochain/incognito-chain/privacy/privacy_v1/schnorr"
	"github.com/incognitochain/incognito-chain/privacy/privacy_v2/mlsag"
	"github.com/incognitochain/incognito-chain/transaction/tx_generic"
	"github.com/incognitochain/incognito-chain/transaction/tx_ver2"
)

func createMlsagSigHost(ring *mlsag.Ring, pi int, hashedMessage []byte, inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, senderSK *privacy.PrivateKey, commitmentToZero *privacy.Point, tx *tx_ver2.Tx) error {
	sumRand := new(privacy.Scalar).FromUint64(0)
	for _, in := range inputCoins {
		sumRand.Add(sumRand, in.GetRandomness())
	}
	for _, out := range outputCoins {
		sumRand.Sub(sumRand, out.GetRandomness())
	}

	privKeysMlsag := make([]*privacy.Scalar, len(inputCoins)+1)
	for i := 0; i < len(inputCoins); i++ {
		var err error
		privKeysMlsag[i], err = inputCoins[i].ParsePrivateKeyOfCoin(*senderSK)
		if err != nil {
			return err
		}
	}
	commitmentToZeroRecomputed := new(privacy.Point).ScalarMult(privacy.PedCom.G[privacy.PedersenRandomnessIndex], sumRand)
	match := privacy.IsPointEqual(commitmentToZeroRecomputed, commitmentToZero)
	if !match {
		return errors.New("Error : asset tag sum or commitment sum mismatch")
	}
	privKeysMlsag[len(inputCoins)] = sumRand
	sag := mlsag.NewMlsag(privKeysMlsag, ring, pi)
	// sk, err := privacy.ArrayScalarToBytes(&privKeysMlsag)
	// if err != nil {
	// 	return err
	// }
	// tx.SetPrivateKey(sk) // ???

	// Set Signature
	mlsagSignature, err := sag.Sign(hashedMessage)
	if err != nil {
		return err
	}
	// inputCoins already hold keyImage so set to nil to reduce size
	mlsagSignature.SetKeyImages(nil)
	tx.Sig, err = mlsagSignature.ToBytes()
	return err
}

//signNoPrivacy
func signSchnorrHost(privKey *privacy.PrivateKey, hashedMessage []byte) (signatureBytes []byte, sigPubKey []byte, err error) {
	/****** using Schnorr signature *******/
	// sign with sigPrivKey
	// prepare private key for Schnorr
	sk := new(operation.Scalar).FromBytesS(*privKey)
	r := new(operation.Scalar).FromUint64(0)
	sigKey := new(schnorr.SchnorrPrivateKey)
	sigKey.Set(sk, r)
	signature, err := sigKey.Sign(hashedMessage)
	if err != nil {
		return nil, nil, err
	}

	signatureBytes = signature.Bytes()
	sigPubKey = sigKey.GetPublicKey().GetPublicKey().ToBytesS()
	return signatureBytes, sigPubKey, nil
}

func createMlsagSigCAHost(ring *mlsag.Ring, pi int, hashedMessage []byte, inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, outputSharedSecrets []*privacy.Point, params *tx_generic.TxPrivacyInitParams, shardID byte, commitmentsToZero []*privacy.Point, tx *tx_ver2.Tx) error {
	tokenID := params.TokenID
	if tokenID == nil {
		tokenID = &common.PRVCoinID
	}
	rehashed := privacy.HashToPoint(tokenID[:])
	sumRand := new(privacy.Scalar).FromUint64(0)

	privKeysMlsag := make([]*privacy.Scalar, len(inputCoins)+2)
	sumInputAssetTagBlinders := new(privacy.Scalar).FromUint64(0)
	numOfInputs := new(privacy.Scalar).FromUint64(uint64(len(inputCoins)))
	numOfOutputs := new(privacy.Scalar).FromUint64(uint64(len(outputCoins)))

	senderSK := params.SenderSK
	mySkBytes := (*senderSK)[:]
	for i := 0; i < len(inputCoins); i += 1 {
		var err error
		privKeysMlsag[i], err = inputCoins[i].ParsePrivateKeyOfCoin(*senderSK)
		if err != nil {
			return fmt.Errorf("Cannot parse private key of coin %v", err)
		}

		inputCoin_specific, ok := inputCoins[i].(*privacy.CoinV2)
		if !ok || inputCoin_specific.GetAssetTag() == nil {
			return errors.New("Cannot cast a coin as v2-CA")
		}

		isUnblinded := privacy.IsPointEqual(rehashed, inputCoin_specific.GetAssetTag())
		if isUnblinded {
			fmt.Printf("Signing TX : processing an unblinded input coin")
		}

		sharedSecret := new(privacy.Point).Identity()
		bl := new(privacy.Scalar).FromUint64(0)
		if !isUnblinded {
			sharedSecret, err = inputCoin_specific.RecomputeSharedSecret(mySkBytes)
			if err != nil {
				return fmt.Errorf("Cannot recompute shared secret : %v", err)
			}

			bl, err = privacy.ComputeAssetTagBlinder(sharedSecret)
			if err != nil {
				return err
			}
		}

		fmt.Printf("CA-MLSAG : processing input asset tag %s\n", string(inputCoin_specific.GetAssetTag().MarshalText()))
		fmt.Printf("Shared secret is %s\n", string(sharedSecret.MarshalText()))
		fmt.Printf("Blinder is %s\n", string(bl.MarshalText()))
		v := inputCoin_specific.GetAmount()
		fmt.Printf("Value is %d\n", v.ToUint64Little())
		effectiveRCom := new(privacy.Scalar).Mul(bl, v)
		effectiveRCom.Add(effectiveRCom, inputCoin_specific.GetRandomness())

		sumInputAssetTagBlinders.Add(sumInputAssetTagBlinders, bl)
		sumRand.Add(sumRand, effectiveRCom)
	}
	sumInputAssetTagBlinders.Mul(sumInputAssetTagBlinders, numOfOutputs)

	sumOutputAssetTagBlinders := new(privacy.Scalar).FromUint64(0)

	var err error
	for i, oc := range outputCoins {
		if oc.GetAssetTag() == nil {
			return errors.New("Cannot cast a coin as v2-CA")
		}
		// lengths between 0 and len(outputCoins) were rejected before
		bl := new(privacy.Scalar).FromUint64(0)
		isUnblinded := privacy.IsPointEqual(rehashed, oc.GetAssetTag())
		if isUnblinded {
			fmt.Printf("Signing TX : processing an unblinded output coin")
		} else {
			fmt.Printf("Shared secret is %s\n", string(outputSharedSecrets[i].MarshalText()))
			bl, err = privacy.ComputeAssetTagBlinder(outputSharedSecrets[i])
			if err != nil {
				return err
			}
		}
		fmt.Printf("CA-MLSAG : processing output asset tag %s\n", string(oc.GetAssetTag().MarshalText()))
		fmt.Printf("Blinder is %s\n", string(bl.MarshalText()))

		v := oc.GetAmount()
		fmt.Printf("Value is %d\n", v.ToUint64Little())
		effectiveRCom := new(privacy.Scalar).Mul(bl, v)
		effectiveRCom.Add(effectiveRCom, oc.GetRandomness())
		sumOutputAssetTagBlinders.Add(sumOutputAssetTagBlinders, bl)
		sumRand.Sub(sumRand, effectiveRCom)
	}
	sumOutputAssetTagBlinders.Mul(sumOutputAssetTagBlinders, numOfInputs)

	// 2 final elements in `private keys` for MLSAG
	assetSum := new(privacy.Scalar).Sub(sumInputAssetTagBlinders, sumOutputAssetTagBlinders)
	firstCommitmentToZeroRecomputed := new(privacy.Point).ScalarMult(privacy.PedCom.G[privacy.PedersenRandomnessIndex], assetSum)
	secondCommitmentToZeroRecomputed := new(privacy.Point).ScalarMult(privacy.PedCom.G[privacy.PedersenRandomnessIndex], sumRand)
	if len(commitmentsToZero) != 2 {
		fmt.Errorf("Received %d points to check when signing MLSAG", len(commitmentsToZero))
		return errors.New("Error : need exactly 2 points for MLSAG double-checking")
	}
	match1 := privacy.IsPointEqual(firstCommitmentToZeroRecomputed, commitmentsToZero[0])
	match2 := privacy.IsPointEqual(secondCommitmentToZeroRecomputed, commitmentsToZero[1])
	if !match1 || !match2 {
		return errors.New("Error : asset tag sum or commitment sum mismatch")
	}

	fmt.Printf("Last 2 private keys will correspond to points %s and %s", firstCommitmentToZeroRecomputed.MarshalText(), secondCommitmentToZeroRecomputed.MarshalText())

	privKeysMlsag[len(inputCoins)] = assetSum
	privKeysMlsag[len(inputCoins)+1] = sumRand

	sag := mlsag.NewMlsag(privKeysMlsag, ring, pi)
	sk, err := privacy.ArrayScalarToBytes(&privKeysMlsag)
	if err != nil {
		return fmt.Errorf("tx.SigPrivKey cannot parse arrayScalar to Bytes, error %v ", err)
	}
	tx.SetPrivateKey(sk)

	// Set Signature
	mlsagSignature, err := sag.SignConfidentialAsset(hashedMessage)
	if err != nil {
		return fmt.Errorf("Cannot signOnMessage mlsagSignature, error %v ", err)
	}
	// inputCoins already hold keyImage so set to nil to reduce size
	mlsagSignature.SetKeyImages(nil)
	tx.Sig, err = mlsagSignature.ToBytes()
	return err
}
