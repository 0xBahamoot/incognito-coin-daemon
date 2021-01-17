package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/rpcserver/bean"
	"github.com/incognitochain/incognito-chain/transaction/tx_generic"
	"github.com/incognitochain/incognito-chain/transaction/tx_ver2"
	"github.com/incognitochain/incognito-chain/transaction/utils"
)

var pendingTx []string
var pendingTxCoins map[string][]string

type onGoingTxCreationStruct struct {
}

var onGoingTxCreation onGoingTxCreationStruct

func CreateTxPRV(account *Account, tokenID string, paymentInfo []*privacy.PaymentInfo, metadataParam metadata.Metadata) (metadata.Transaction, error) {
	//create tx param
	rawTxParam := bean.CreateRawTxParam{
		ShardIDSender:        account.ShardID,
		PaymentInfos:         paymentInfo,
		HasPrivacyCoin:       true,
		Info:                 nil,
		EstimateFeeCoinPerKb: 0,
	}
	tx, err := buildRawTransaction(&rawTxParam, metadataParam)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func CreateTxToken(account *Account, tokenID string, paymentInfo []*privacy.PaymentInfo, metadataParam metadata.Metadata) (metadata.Transaction, error) {
	//create tx param
	rawTxParam := bean.CreateRawTxParam{
		ShardIDSender:        account.ShardID,
		PaymentInfos:         paymentInfo,
		HasPrivacyCoin:       true,
		Info:                 nil,
		EstimateFeeCoinPerKb: 0,
	}
	tx, err := buildRawTransaction(account, &rawTxParam, metadataParam)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func buildRawTransaction(account *Account, params *bean.CreateRawTxParam, meta metadata.Metadata) (metadata.Transaction, error) {
	var tx tx_ver2.Tx

	// get output coins to spend and real fee

	inputCoins, realFee, err := chooseCoinsForAccount(account,
		params.PaymentInfos, params.EstimateFeeCoinPerKb, 0,
		params.SenderKeySet, params.ShardIDSender, params.HasPrivacyCoin,
		meta, nil)
	if err1 != nil {
		return err
	}

	// rewrite TxBase InitializeTxAndParams
	initializingParams := tx_generic.NewTxPrivacyInitParams(dummyPrivateKeys[0],
		paymentInfoOut, inputCoins,
		sumIn-sumOut, hasPrivacyForPRV,
		dummyDB,
		&common.PRVCoinID,
		nil,
		[]byte{},
	)

	params, ok := paramsInterface.(*tx_generic.TxPrivacyInitParams)
	if !ok {
		return errors.New("params of tx Init is not TxPrivacyInitParam")
	}

	jsb, _ := json.Marshal(params)
	utils.Logger.Log.Infof("Create TX v2 with params %s", string(jsb))
	if err := tx_generic.ValidateTxParams(params); err != nil {
		return err
	}

	// Init tx and params (tx and params will be changed)
	if err := tx.InitializeTxAndParams(params); err != nil {
		return err
	}
	// check this IsNonPrivacyNonInput (request sign from device)
	if len(params.InputCoins) == 0 && params.Fee == 0 && !params.HasPrivacy {
		//Logger.Log.Debugf("len(inputCoins) == 0 && fee == 0 && !hasPrivacy\n")
		tx.sigPrivKey = *params.SenderSK
		if tx.Sig, tx.SigPubKey, err = SignNoPrivacy(params.SenderSK, tx.Hash()[:]); err != nil {
			utils.Logger.Log.Error(errors.New(fmt.Sprintf("Cannot signOnMessage tx %v\n", err)))
			return true, utils.NewTransactionErr(utils.SignTxError, err)
		}
		return true, nil
	}

	// proveTxToken

	//validate tx param ValidateTxParams

	//conceal coin
	return tx, nil
}

// use for prv tx
func proveTxPRV(tx *tx_ver2.Tx, params *tx_generic.TxPrivacyInitParams) error {
	outputCoins, err := utils.NewCoinV2ArrayFromPaymentInfoArray(params.PaymentInfo, params.TokenID, params.StateDB)
	if err != nil {
		fmt.Printf("Cannot parse outputCoinV2 to outputCoins, error %v \n", err)
		return err
	}

	inputCoins := params.InputCoins

	// gen tx proof
	tx.Proof, err = privacy.ProveV2(inputCoins, outputCoins, nil, false, params.PaymentInfo)
	if err != nil {
		utils.Logger.Log.Errorf("Error in privacy_v2.Prove, error %v ", err)
		return err
	}

	if tx.ShouldSignMetaData() {
		if err := signMetadata(tx); err != nil {
			panic(err)
		}
	}

	// ringSig + mlsag
	// err := tx.signOnMessage(inputCoins, outputCoins, params, tx.Hash()[:])
	return nil
}

func proveTxToken(tx *tx_ver2.Tx, params *tx_generic.TxPrivacyInitParams) error {
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
