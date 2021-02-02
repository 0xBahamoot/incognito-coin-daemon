package main

import "github.com/incognitochain/incognito-chain/privacy"

func createPrivKeyMlsagLedger(txCID int, inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, commitmentToZero *privacy.Point) ([]*privacy.Scalar, error) {
	privKeyMlsag := make([]*privacy.Scalar, len(inputCoins)+1)

	return privKeyMlsag, nil
}

//signNoPrivacy
func signSchnorrLedger(txCID int, hashedMessage []byte) (signatureBytes []byte, sigPubKey []byte, err error) {
	return
}
