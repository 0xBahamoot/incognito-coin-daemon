package main

import "github.com/incognitochain/incognito-chain/metadata"

func NewStakingMetadata(metadataParam interface{}) (*metadata.StakingMetadata, error) {
	var result metadata.StakingMetadata
	// handleCreateRawStakingTransaction

	return &result, nil
}

func NewStopStakingMetadata(metadataParam interface{}) (*metadata.StopAutoStakingMetadata, error) {
	var result metadata.StopAutoStakingMetadata
	// handleCreateRawStopAutoStakingTransaction

	return &result, nil
}

//used for both prv & pToken Contribution
func NewPDEContribution(metadataParam interface{}) (*metadata.PDEContribution, error) {
	var result metadata.PDEContribution
	// handleCreateRawTxWithPRVContribution
	return &result, nil
}

func NewPDECrossPoolTradeRequest(metadataParam interface{}) (*metadata.PDECrossPoolTradeRequest, error) {
	var result metadata.PDECrossPoolTradeRequest
	// handleCreateRawTxWithPRVCrossPoolTradeReq
	return &result, nil
}

func NewPDETradeRequest(metadataParam interface{}) (*metadata.PDETradeRequest, error) {
	var result metadata.PDETradeRequest
	// handleCreateRawTxWithPTokenTradeReq
	return &result, nil
}
