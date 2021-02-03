package main

import (
	"errors"
	"fmt"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
	"github.com/incognitochain/incognito-chain/incognitokey"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/wallet"
)

func NewStakingMetadata(account *Account, metadataParam interface{}) (*metadata.StakingMetadata, error) {
	paramsArray := common.InterfaceSlice(metadataParam)
	var result metadata.StakingMetadata
	// handleCreateRawStakingTransaction
	// prepare meta data
	data, ok := paramsArray[4].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Invalid Data For Staking Transaction %+v", paramsArray[4])
	}

	stakingType, ok := data["StakingType"].(float64)
	if !ok {
		return nil, fmt.Errorf("Invalid Staking Type For Staking Transaction %+v", data["StakingType"])
	}

	candidatePaymentAddress, ok := data["CandidatePaymentAddress"].(string)
	if !ok {
		return nil, fmt.Errorf("Invalid Producer Payment Address for Staking Transaction %+v", data["CandidatePaymentAddress"])
	}

	// Get private seed, a.k.a mining key
	privateSeed, ok := data["PrivateSeed"].(string)
	if !ok {
		return nil, fmt.Errorf("Invalid Private Seed For Staking Transaction %+v", data["PrivateSeed"])
	}
	privateSeedBytes, ver, errDecode := base58.Base58Check{}.Decode(privateSeed)
	if (errDecode != nil) || (ver != common.ZeroByte) {
		return nil, errors.New("Decode privateseed failed!")
	}

	//Get RewardReceiver Payment Address
	rewardReceiverPaymentAddress, ok := data["RewardReceiverPaymentAddress"].(string)
	if !ok {
		return nil, fmt.Errorf("Invalid Reward Receiver Payment Address For Staking Transaction %+v", data["RewardReceiverPaymentAddress"])
	}

	//Get auto staking flag
	autoReStaking, ok := data["AutoReStaking"].(bool)
	if !ok {
		return nil, fmt.Errorf("Invalid auto restaking flag %+v", data["AutoReStaking"])
	}

	// Get candidate publickey
	candidateWallet, err := wallet.Base58CheckDeserialize(candidatePaymentAddress)
	if err != nil || candidateWallet == nil {
		return nil, errors.New("Base58CheckDeserialize candidate Payment Address failed")
	}
	pk := candidateWallet.KeySet.PaymentAddress.Pk

	committeePK, err := incognitokey.NewCommitteeKeyFromSeed(privateSeedBytes, pk)
	if err != nil {
		return nil, errors.New("Cannot get payment address")
	}

	committeePKBytes, err := committeePK.Bytes()
	if err != nil {
		return nil, errors.New("Cannot import key set")
	}
	funderPaymentAddress := account.PAstr

	stakingMetadata, err := metadata.NewStakingMetadata(
		int(stakingType), funderPaymentAddress, rewardReceiverPaymentAddress,
		httpServer.config.ChainParams.StakingAmountShard,
		base58.Base58Check{}.Encode(committeePKBytes, common.ZeroByte), autoReStaking)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func NewStopStakingMetadata(account *Account, metadataParam interface{}) (*metadata.StopAutoStakingMetadata, error) {
	var result metadata.StopAutoStakingMetadata
	// handleCreateRawStopAutoStakingTransaction

	return &result, nil
}

//used for both prv & pToken Contribution
func NewPDEContribution(account *Account, metadataParam interface{}) (*metadata.PDEContribution, error) {
	var result metadata.PDEContribution
	// handleCreateRawTxWithPRVContribution
	return &result, nil
}

func NewPDECrossPoolTradeRequest(account *Account, metadataParam interface{}) (*metadata.PDECrossPoolTradeRequest, error) {
	var result metadata.PDECrossPoolTradeRequest
	// handleCreateRawTxWithPRVCrossPoolTradeReq
	return &result, nil
}

func NewPDETradeRequest(account *Account, metadataParam interface{}) (*metadata.PDETradeRequest, error) {
	var result metadata.PDETradeRequest
	// handleCreateRawTxWithPTokenTradeReq
	return &result, nil
}
