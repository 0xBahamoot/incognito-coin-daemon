package main

type API_create_tx_req struct {
	ViaLedger bool
	TxType    int
	TxParam   interface{}
}

type API_sync_status_rep struct {
}
