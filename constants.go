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
	TXTRANFER_PRV = iota
	TXTRANFER_TOKEN
	TXSTAKING
	TXSTOPSTAKING
	TXTRADE
	TXTRADE_TOKEN
	TXTRADE_CROSSPOOL
	TXTRADE_CROSSPOOL_TOKEN
	TXCONTRIBUTION
	TXCONTRIBUTION_TOKEN
)

const (
	MainNetStakingAmountShard = 1750000000000 // 1750 PRV = 1750 * 10^9 nano PRV

)

var (
	DB_ACCOUNTKEY   = []byte("account-")
	DB_COINSTATEKEY = []byte("coinstate-")
	DB_COININDEXKEY = []byte("coinidx-")
)
