package main

import (
	"errors"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
	"github.com/incognitochain/incognito-chain/privacy/coin"
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
