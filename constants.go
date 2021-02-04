package main

import "time"

var (
	usedkeyimage             = []byte{0x01}
	compatibleLedgerVersions = []int{}
)

const (
	defaultBalanceWatchInterval = 5 * time.Second
)

const (
	TXTRANFERPRV = iota
	TXTRANFERTOKEN
	TXSTAKING
	TXSTOPSTAKING
	TXTRADECROSSPOOL
	TXTRADE
	TXCONTRIBUTION
)

const (
	MainNetStakingAmountShard = 1750000000000 // 1750 PRV = 1750 * 10^9 nano PRV

)
