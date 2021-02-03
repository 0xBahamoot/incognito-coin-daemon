package main

import "github.com/incognitochain/incognito-chain/privacy"

//createPrivKeyMlsagLedger (ringSig)
func createPrivKeyMlsagLedger(instance *txCreationInstance, inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, commitmentToZero *privacy.Point) ([]byte, error) {
	sigBytes := []byte{}
	// sumRand := new(privacy.Scalar).FromUint64(0)
	// for _, in := range inputCoins {
	// 	sumRand.Add(sumRand, in.GetRandomness())
	// }
	// for _, out := range outputCoins {
	// 	sumRand.Sub(sumRand, out.GetRandomness())
	// }

	// privKeyMlsag := make([]*privacy.Scalar, len(inputCoins)+1)
	// for i := 0; i < len(inputCoins); i++ {
	// 	var err error
	// 	privKeyMlsag[i], err = inputCoins[i].ParsePrivateKeyOfCoin(*senderSK)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }
	// commitmentToZeroRecomputed := new(privacy.Point).ScalarMult(privacy.PedCom.G[privacy.PedersenRandomnessIndex], sumRand)
	// match := privacy.IsPointEqual(commitmentToZeroRecomputed, commitmentToZero)
	// if !match {
	// 	return nil, errors.New("Error : asset tag sum or commitment sum mismatch")
	// }
	// privKeyMlsag[len(inputCoins)] = sumRand
	return sigBytes, nil
}

//signNoPrivacy
func signSchnorrLedger(instance *txCreationInstance, hashedMessage []byte) (signatureBytes []byte, sigPubKey []byte, err error) {
	// sk := new(operation.Scalar).FromBytesS(*privKey)
	// r := new(operation.Scalar).FromUint64(0)
	// sigKey := new(schnorr.SchnorrPrivateKey)
	// sigKey.Set(sk, r)
	// signature, err := sigKey.Sign(hashedMessage)
	// if err != nil {
	// 	return nil, nil, err
	// }

	// signatureBytes = signature.Bytes()
	// sigPubKey = sigKey.GetPublicKey().GetPublicKey().ToBytesS()
	return
}
