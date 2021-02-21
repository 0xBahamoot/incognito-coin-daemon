package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/privacy/operation"
	"github.com/incognitochain/incognito-chain/privacy/privacy_v1/schnorr"
	"github.com/incognitochain/incognito-chain/privacy/privacy_v2/mlsag"
	"github.com/incognitochain/incognito-chain/transaction/tx_generic"
	"github.com/incognitochain/incognito-chain/transaction/tx_ver2"
	"github.com/incognitochain/incognito-chain/transaction/utils"
)

//createMlsagSigLedger (ringSig)
func createMlsagSigLedger(instance *txCreationInstance, ring *mlsag.Ring, pi int, hashedMessage []byte, inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, senderSK *privacy.PrivateKey, commitmentToZero *privacy.Point, tx *tx_ver2.Tx) error {

	message32byte := [32]byte{}
	copy(message32byte[:], hashedMessage)

	sumRand := new(privacy.Scalar).FromUint64(0)
	for _, in := range inputCoins {
		sumRand.Add(sumRand, in.GetRandomness())
	}
	for _, out := range outputCoins {
		sumRand.Sub(sumRand, out.GetRandomness())
	}

	commitmentToZeroRecomputed := new(privacy.Point).ScalarMult(privacy.PedCom.G[privacy.PedersenRandomnessIndex], sumRand)
	match := privacy.IsPointEqual(commitmentToZeroRecomputed, commitmentToZero)
	if !match {
		return errors.New("Error : asset tag sum or commitment sum mismatch")
	}

	//coinsH
	coinsH, err := ExtractCoinH(inputCoins, instance.AccountState.Account.OTAKey)
	if err != nil {
		return err
	}
	sumRandPK := []*operation.Scalar{sumRand}
	sumRandPubkey := mlsag.ParseKeyImages(sumRandPK)

	coinsH = append(coinsH, sumRandPK[0].ToBytesS())

	alpha, r := createRandomChallenges(len(inputCoins)+1, len(ring.GetKeys()), pi)
	_ = alpha // not used this alpha

	coinKMs := []*operation.Point{}
	for _, coin := range inputCoins {
		coinKMs = append(coinKMs, coin.GetKeyImage())
	}
	coinKMs = append(coinKMs, sumRandPubkey[0])

	if err := RequestLedgerGenAlpha(instance, len(inputCoins)+1); err != nil {
		return err
	}

	if err := RequestLedgerGenCoinPrivate(instance, coinsH); err != nil {
		return err
	}

	// calculate C
	c, err := RequestLedgerCalculateC(instance, message32byte, pi, r, ring, coinKMs)
	if err != nil {
		return err
	}

	rPi, err := RequestLedgerCalculateR(instance, len(inputCoins)+1, c[pi])
	if err != nil {
		return err
	}
	r[pi] = rPi
	sig := &mlsag.MlsagSig{}
	sig.SetC(c[0])
	sig.SetR(r)
	tx.Sig, err = sig.ToBytes()
	return err
}

//signNoPrivacy
func signSchnorrLedger(instance *txCreationInstance, hashedMessage []byte) (signatureBytes []byte, sigPubKey []byte, err error) {
	sig, err := RequestLedgerSignSchnorr(instance, hashedMessage)
	return sig, nil, err
}

func createMlsagSigCALedger(instance *txCreationInstance, ring *mlsag.Ring, pi int, hashedMessage []byte, inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, outputSharedSecrets []*privacy.Point, params *tx_generic.TxPrivacyInitParams, shardID byte, commitmentsToZero []*privacy.Point, tx *tx_ver2.Tx) error {
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
				fmt.Errorf("Cannot recompute shared secret : %v", err)
				return err
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
		return utils.NewTransactionErr(utils.UnexpectedError, errors.New("Error : need exactly 2 points for MLSAG double-checking"))
	}
	match1 := privacy.IsPointEqual(firstCommitmentToZeroRecomputed, commitmentsToZero[0])
	match2 := privacy.IsPointEqual(secondCommitmentToZeroRecomputed, commitmentsToZero[1])
	if !match1 || !match2 {
		return utils.NewTransactionErr(utils.UnexpectedError, errors.New("Error : asset tag sum or commitment sum mismatch"))
	}

	fmt.Printf("Last 2 private keys will correspond to points %s and %s", firstCommitmentToZeroRecomputed.MarshalText(), secondCommitmentToZeroRecomputed.MarshalText())

	privKeysMlsag[len(inputCoins)] = assetSum
	privKeysMlsag[len(inputCoins)+1] = sumRand

	sag := mlsag.NewMlsag(privKeysMlsag, ring, pi)
	sk, err := privacy.ArrayScalarToBytes(&privKeysMlsag)
	if err != nil {
		utils.Logger.Log.Errorf("tx.SigPrivKey cannot parse arrayScalar to Bytes, error %v ", err)
		return err
	}
	tx.SetPrivateKey(sk)

	// Set Signature
	mlsagSignature, err := sag.SignConfidentialAsset(hashedMessage)
	if err != nil {
		utils.Logger.Log.Errorf("Cannot signOnMessage mlsagSignature, error %v ", err)
		return err
	}
	// inputCoins already hold keyImage so set to nil to reduce size
	mlsagSignature.SetKeyImages(nil)
	tx.Sig, err = mlsagSignature.ToBytes()
	return err
}

func RequestLedgerSignSchnorr(inst *txCreationInstance, message []byte) ([]byte, error) {
	request := LedgerRequest{
		Cmd: "signschnorr",
	}

	type ReqStruct struct {
		PedRandom  []byte
		PedPrivate []byte
		Randomness []byte
		Message    []byte
	}

	pedRandom := operation.PedCom.G[operation.PedersenRandomnessIndex].GetKey()
	pedPrivate := operation.PedCom.G[operation.PedersenPrivateKeyIndex].GetKey()
	r := new(privacy.Scalar).FromUint64(0)
	requestData := ReqStruct{
		PedRandom:  pedRandom[:],
		PedPrivate: pedPrivate[:],
		Randomness: r.ToBytesS(),
		Message:    message,
	}

	requestDataBytes, _ := json.Marshal(requestData)
	request.Data = requestDataBytes

	respondBytes, err := inst.SendCmdRequestToLedger(&request)
	if err != nil {
		return nil, err
	}

	eBytes := respondBytes[:32]
	z1Bytes := respondBytes[32:64]
	z2Bytes := []byte{}
	if len(respondBytes)/32 == 3 {
		z2Bytes = respondBytes[64:]
	}
	sigBytes := append(eBytes, append(z1Bytes, z2Bytes...)...)
	//double check
	schnorrSig := schnorr.SchnSignature{}
	err = schnorrSig.SetBytes(sigBytes)

	return schnorrSig.Bytes(), err
}

func RequestLedgerGenAlpha(inst *txCreationInstance, alphaLen int) error {
	request := LedgerRequest{
		Cmd: "genalpha",
	}

	type ReqStruct struct {
		AlphaLength int
	}
	requestData := ReqStruct{
		AlphaLength: alphaLen,
	}
	requestDataBytes, _ := json.Marshal(requestData)

	request.Data = requestDataBytes
	respondBytes, err := inst.SendCmdRequestToLedger(&request)
	if err != nil {
		return err
	}
	if string(respondBytes) != "success" {
		return errors.New("unexpected gen alpha err")
	}
	return nil
}

func RequestLedgerGenCoinPrivate(inst *txCreationInstance, coinsH [][]byte) error {
	request := LedgerRequest{
		Cmd: "gencoinprivate",
	}

	type ReqStruct struct {
		CoinsH [][]byte
	}
	requestData := ReqStruct{
		CoinsH: coinsH,
	}
	requestDataBytes, _ := json.Marshal(requestData)

	request.Data = requestDataBytes

	respondBytes, err := inst.SendCmdRequestToLedger(&request)
	if err != nil {
		return err
	}
	if string(respondBytes) != "success" {
		return errors.New("unexpected gen alpha err")
	}
	return nil
}

func RequestLedgerCalculateC(inst *txCreationInstance, message [32]byte, pi int, r [][]*operation.Scalar, ring *mlsag.Ring, coinsKeyImage []*operation.Point) ([]*operation.Scalar, error) {
	R := ring.GetKeys()
	n := len(R)
	c := make([]*operation.Scalar, n)

	//calculate 1st C
	request := LedgerRequest{
		Cmd: "calculatec",
	}

	type ReqStruct struct {
		Rpi     [][]byte
		PedComG []byte
	}
	requestData := ReqStruct{
		PedComG: operation.PedCom.G[operation.PedersenRandomnessIndex].ToBytesS(),
	}
	rPi := [][]byte{}
	for _, r := range R[pi] {
		rPi = append(rPi, r.ToBytesS())
	}
	requestData.Rpi = rPi
	requestDataBytes, _ := json.Marshal(requestData)

	request.Data = requestDataBytes

	respondBytes, err := inst.SendCmdRequestToLedger(&request)
	if err != nil {
		return nil, err
	}
	var b []byte
	b = append(b, message[:]...)
	b = append(b, respondBytes...)

	firstC := operation.HashToScalar(b)

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
	return c, nil
}

func RequestLedgerCalculateR(inst *txCreationInstance, coinLength int, cPi *operation.Scalar) ([]*operation.Scalar, error) {
	request := LedgerRequest{
		Cmd: "calculater",
	}

	type ReqStruct struct {
		CoinLength int
		Cpi        []byte
	}
	requestData := ReqStruct{
		CoinLength: coinLength,
		Cpi:        cPi.ToBytesS(),
	}
	requestDataBytes, _ := json.Marshal(requestData)

	request.Data = requestDataBytes
	respondBytes, err := inst.SendCmdRequestToLedger(&request)
	if err != nil {
		return nil, err
	}
	var rArray [][]byte
	err = json.Unmarshal(respondBytes, &rArray)
	if err != nil {
		return nil, err
	}

	var result []*operation.Scalar
	for i := 0; i < coinLength; i++ {
		r := operation.Scalar{}
		r.FromBytesS(rArray[i])
		result = append(result, &r)
	}
	return result, nil
}
