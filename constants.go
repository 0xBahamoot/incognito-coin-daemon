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
)
