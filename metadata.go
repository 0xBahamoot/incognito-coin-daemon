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
	arrayParams := common.InterfaceSlice(metadataParam)
	var result *metadata.StakingMetadata
	// prepare meta data
	data, ok := arrayParams[3].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Invalid Data For Staking Transaction %+v", arrayParams[3])
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
		return nil, errors.New("decode privateseed failed")
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

	result, err = metadata.NewStakingMetadata(
		int(stakingType), funderPaymentAddress, rewardReceiverPaymentAddress,
		MainNetStakingAmountShard,
		base58.Base58Check{}.Encode(committeePKBytes, common.ZeroByte), autoReStaking)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func NewStopStakingMetadata(account *Account, metadataParam interface{}) (*metadata.StopAutoStakingMetadata, error) {
	arrayParams := common.InterfaceSlice(metadataParam)
	var result *metadata.StopAutoStakingMetadata
	//Get data to create meta data
	data, ok := arrayParams[3].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Invalid Staking Type For Staking Transaction %+v", arrayParams[3])
	}

	//Get staking type
	stopAutoStakingType, ok := data["StopAutoStakingType"].(float64)
	if !ok {
		return nil, fmt.Errorf("Invalid Staking Type For Staking Transaction %+v", data["StopAutoStakingType"])
	}

	//Get Candidate Payment Address
	candidatePaymentAddress, ok := data["CandidatePaymentAddress"].(string)
	if !ok {
		return nil, fmt.Errorf("Invalid Producer Payment Address for Staking Transaction %+v", data["CandidatePaymentAddress"])
	}
	// Get private seed, a.k.a mining key
	privateSeed, ok := data["PrivateSeed"].(string)
	if !ok {
		return nil, fmt.Errorf("Invalid Private Seed for Staking Transaction %+v", data["PrivateSeed"])
	}
	privateSeedBytes, ver, err := base58.Base58Check{}.Decode(privateSeed)
	if (err != nil) || (ver != common.ZeroByte) {
		return nil, errors.New("decode privateseed failed")
	}

	// Get candidate publickey
	candidateWallet, err := wallet.Base58CheckDeserialize(candidatePaymentAddress)
	if err != nil || candidateWallet == nil {
		return nil, errors.New("Base58CheckDeserialize candidate Payment Address failed")
	}
	pk := candidateWallet.KeySet.PaymentAddress.Pk

	committeePK, err := incognitokey.NewCommitteeKeyFromSeed(privateSeedBytes, pk)
	if err != nil {
		return nil, err
	}

	committeePKBytes, err := committeePK.Bytes()
	if err != nil {
		return nil, err
	}

	result, err = metadata.NewStopAutoStakingMetadata(int(stopAutoStakingType), base58.Base58Check{}.Encode(committeePKBytes, common.ZeroByte))
	if err != nil {
		return nil, err
	}
	return result, nil
}

//used for both prv & pToken Contribution
func NewPDEContribution(account *Account, metadataParam interface{}) (*metadata.PDEContribution, error) {
	var result *metadata.PDEContribution
	arrayParams := common.InterfaceSlice(metadataParam)
	// get meta data from params
	data, ok := arrayParams[3].(map[string]interface{})
	if !ok {
		return nil, errors.New("metadata is invalid")
	}
	pdeContributionPairID, ok := data["PDEContributionPairID"].(string)
	if !ok {
		return nil, errors.New("metadata is invalid")
	}
	contributorAddressStr, ok := data["ContributorAddressStr"].(string)
	if !ok {
		return nil, errors.New("metadata is invalid")
	}
	contributedAmount, err := common.AssertAndConvertNumber(data["ContributedAmount"])
	if err != nil {
		return nil, err
	}
	tokenIDStr, ok := data["TokenIDStr"].(string)
	if !ok {
		return nil, errors.New("metadata is invalid")
	}

	result, _ = metadata.NewPDEContribution(
		pdeContributionPairID,
		contributorAddressStr,
		contributedAmount,
		tokenIDStr,
		metadata.PDEPRVRequiredContributionRequestMeta,
	)
	return result, nil
}

func NewPDECrossPoolTradeRequest(account *Account, metadataParam interface{}) (*metadata.PDECrossPoolTradeRequest, error) {
	arrayParams := common.InterfaceSlice(metadataParam)
	var result *metadata.PDECrossPoolTradeRequest
	// get meta data from params
	data, ok := arrayParams[3].(map[string]interface{})
	if !ok {
		return nil, errors.New("metadata is invalid")
	}
	tokenIDToBuyStr, ok := data["TokenIDToBuyStr"].(string)
	if !ok {
		return nil, errors.New("metadata is invalid")
	}
	tokenIDToSellStr, ok := data["TokenIDToSellStr"].(string)
	if !ok {
		return nil, errors.New("metadata is invalid")
	}
	sellAmount, err := common.AssertAndConvertNumber(data["SellAmount"])
	if err != nil {
		return nil, err
	}
	traderAddressStr, ok := data["TraderAddressStr"].(string)
	if !ok {
		return nil, errors.New("metadata is invalid")
	}
	minAcceptableAmount, err := common.AssertAndConvertNumber(data["MinAcceptableAmount"])
	if err != nil {
		return nil, err
	}
	tradingFee, err := common.AssertAndConvertNumber(data["TradingFee"])
	if err != nil {
		return nil, err
	}
	traderOTAPublicKeyStr, traderOTAtxRandomStr, err := GenerateOTAFromPaymentAddress(traderAddressStr)
	if err != nil {
		return nil, err
	}
	traderSubOTAPublicKeyStr, traderSubOTAtxRandomStr, err := GenerateOTAFromPaymentAddress(traderAddressStr)
	if err != nil {
		return nil, err
	}

	result, _ = metadata.NewPDECrossPoolTradeRequest(
		tokenIDToBuyStr,
		tokenIDToSellStr,
		sellAmount,
		minAcceptableAmount,
		tradingFee,
		traderOTAPublicKeyStr,
		traderOTAtxRandomStr,
		traderSubOTAPublicKeyStr,
		traderSubOTAtxRandomStr,
		metadata.PDECrossPoolTradeRequestMeta,
	)
	return result, nil
}

func NewPDETradeRequest(account *Account, metadataParam interface{}) (*metadata.PDETradeRequest, error) {
	var result *metadata.PDETradeRequest
	arrayParams := common.InterfaceSlice(metadataParam)
	tokenParamsRaw := arrayParams[3].(map[string]interface{})

	tokenIDToBuyStr, ok := tokenParamsRaw["TokenIDToBuyStr"].(string)
	if !ok {
		return nil, errors.New("metadata is invalid")
	}

	tokenIDToSellStr, ok := tokenParamsRaw["TokenIDToSellStr"].(string)
	if !ok {
		return nil, errors.New("metadata is invalid")
	}

	sellAmount, err := common.AssertAndConvertNumber(tokenParamsRaw["SellAmount"])
	if err != nil {
		return nil, err
	}

	traderAddressStr, ok := tokenParamsRaw["TraderAddressStr"].(string)
	if !ok {
		return nil, errors.New("metadata is invalid")
	}

	minAcceptableAmount, err := common.AssertAndConvertNumber(tokenParamsRaw["MinAcceptableAmount"])
	if err != nil {
		return nil, err
	}

	tradingFee, err := common.AssertAndConvertNumber(tokenParamsRaw["TradingFee"])
	if err != nil {
		return nil, err
	}

	traderOTAPublicKeyStr, traderOTAtxRandomStr, err := GenerateOTAFromPaymentAddress(traderAddressStr)
	if err != nil {
		return nil, err
	}

	result, _ = metadata.NewPDETradeRequest(
		tokenIDToBuyStr,
		tokenIDToSellStr,
		sellAmount,
		minAcceptableAmount,
		tradingFee,
		traderOTAPublicKeyStr,
		traderOTAtxRandomStr,
		metadata.PDETradeRequestMeta,
	)

	return result, nil
}
