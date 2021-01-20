package main

type API_create_tx struct {
	ViaLedger bool
	TxType    int
	TxParam   interface{}
}
