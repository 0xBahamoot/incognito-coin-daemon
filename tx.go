package main

import (
	"errors"
	"fmt"

	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/privacy/key"
	"github.com/incognitochain/incognito-chain/transaction/tx_generic"
	"github.com/incognitochain/incognito-chain/transaction/tx_ver2"
	"github.com/incognitochain/incognito-chain/transaction/utils"
)

var pendingTx []string
var pendingTxCoins map[string][]string

type onGoingTxCreationStruct struct {
}

var onGoingTxCreation onGoingTxCreationStruct

func CreateTxPRV(account *Account, paymentInfo []key.PaymentInfo) error {
	//create tx param

	// rewrite TxBase InitializeTxAndParams
	// check this IsNonPrivacyNonInput (request sign from device)

	//validate tx param ValidateTxParams

	//conceal coin
	return nil
}

func CreateTxToken(account *Account, tokenID string, paymentInfo []key.PaymentInfo) error {
	//create tx param

	// rewrite TxBase InitializeTxAndParams
	// check this IsNonPrivacyNonInput (request sign from device)

	// proveTxPRV

	//validate tx param ValidateTxParams

	//conceal coin
	return nil
}

// use for prv tx
func proveTxPRV(tx *tx_ver2.Tx, params *tx_generic.TxPrivacyInitParams) error {
	outputCoins, err := utils.NewCoinV2ArrayFromPaymentInfoArray(params.PaymentInfo, params.TokenID, params.StateDB)
	if err != nil {
		fmt.Printf("Cannot parse outputCoinV2 to outputCoins, error %v \n", err)
		return err
	}

	// inputCoins is plainCoin because it may have coinV1 with coinV2
	inputCoins := params.InputCoins

	tx.Proof, err = privacy.ProveV2(inputCoins, outputCoins, nil, false, params.PaymentInfo)
	if err != nil {
		utils.Logger.Log.Errorf("Error in privacy_v2.Prove, error %v ", err)
		return err
	}

	if tx.ShouldSignMetaData() {
		// signMetadata
	}

	return nil
}

func signMetadata(tx *tx_ver2.Tx) error {
	metaSig := tx.Metadata.GetSig()
	if metaSig != nil && len(metaSig) > 0 {
		return errors.New("meta.Sig should be empty or nil")
	}
	data := tx.HashWithoutMetadataSig()[:]
	_ = data
	//TO BE SENT TO LEDGER FOR SIGNING
	var signature []byte
	tx.Metadata.SetSig(signature)
	fmt.Println("Signature Detail", tx.Metadata.GetSig())
	return nil
}

func createPrivKeyMlsag(inputCoins []privacy.PlainCoin, outputCoins []*privacy.CoinV2, senderSK *privacy.PrivateKey, commitmentToZero *privacy.Point) ([]*privacy.Scalar, error) {
	sumRand := new(privacy.Scalar).FromUint64(0)
	for _, in := range inputCoins {
		sumRand.Add(sumRand, in.GetRandomness())
	}
	for _, out := range outputCoins {
		sumRand.Sub(sumRand, out.GetRandomness())
	}

	privKeyMlsag := make([]*privacy.Scalar, len(inputCoins)+1)
	for i := 0; i < len(inputCoins); i++ {
		//TO BE SENT TO LEDGER FOR SIGNING

		// var err error
		// privKeyMlsag[i], err = inputCoins[i].ParsePrivateKeyOfCoin(*senderSK)
		// if err != nil {
		// 	utils.Logger.Log.Errorf("Cannot parse private key of coin %v", err)
		// 	return nil, err
		// }
	}
	commitmentToZeroRecomputed := new(privacy.Point).ScalarMult(privacy.PedCom.G[privacy.PedersenRandomnessIndex], sumRand)
	match := privacy.IsPointEqual(commitmentToZeroRecomputed, commitmentToZero)
	if !match {
		return nil, utils.NewTransactionErr(utils.SignTxError, errors.New("Error : asset tag sum or commitment sum mismatch"))
	}
	privKeyMlsag[len(inputCoins)] = sumRand
	return privKeyMlsag, nil
}
