package main

import (
	"errors"
	"fmt"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/privacy/coin"
	"github.com/incognitochain/incognito-chain/privacy/operation"
	"github.com/incognitochain/incognito-chain/wallet"
)

func GenerateOTAFromPaymentAddress(paymentAddressStr string) (string, string, error) {
	keyWallet, err := wallet.Base58CheckDeserialize(paymentAddressStr)
	if err != nil {
		return "", "", err
	}
	if len(keyWallet.KeySet.PaymentAddress.Pk) == 0 {
		return "", "", errors.New("invalid payment address string")
	}

	publickey, txRandom, err := coin.NewOTAFromReceiver(keyWallet.KeySet.PaymentAddress)
	if err != nil {
		return "", "", err
	}
	return base58.Base58Check{}.Encode(publickey.ToBytesS(), common.ZeroByte), base58.Base58Check{}.Encode(txRandom.Bytes(), common.ZeroByte), nil
}

func CreateCustomTokenPrivacyReceiverArray(dataReceiver interface{}) ([]*privacy.PaymentInfo, int64, error) {
	if dataReceiver == nil {
		return nil, 0, fmt.Errorf("data receiver is in valid")
	}
	paymentInfos := []*privacy.PaymentInfo{}
	voutsAmount := int64(0)
	receivers, ok := dataReceiver.(map[string]interface{})
	if !ok {
		return nil, 0, fmt.Errorf("data receiver is in valid")
	}
	for key, value := range receivers {
		keyWallet, err := wallet.Base58CheckDeserialize(key)
		if err != nil {
			return nil, 0, fmt.Errorf("payment info %+v is invalid. Error %v\n", key, err)
		}
		if len(keyWallet.KeySet.PaymentAddress.Pk) == 0 {
			return nil, 0, fmt.Errorf("public key in payment info %+v is invalid\n", key)
		}
		amount, err := common.AssertAndConvertNumber(value)
		if err != nil {
			return nil, 0, fmt.Errorf("amount payment address is invalid. Error %v\n", err)
		}
		temp := &privacy.PaymentInfo{
			PaymentAddress: keyWallet.KeySet.PaymentAddress,
			Amount:         amount,
		}
		paymentInfos = append(paymentInfos, temp)
		voutsAmount += int64(temp.Amount)
	}
	return paymentInfos, voutsAmount, nil
}

func scalarArrayToBytesArray(scalars []*operation.Scalar) []byte {
	var result []byte
	for _, scalar := range scalars {
		result = append(result, scalar.ToBytesS()...)
	}
	return result
}
