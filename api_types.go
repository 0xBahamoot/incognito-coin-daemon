package main

type API_create_tx_req struct {
	ViaLedger bool
	TxType    int
	TxParam   interface{}
}

type API_submit_keyimages_req struct {
}

type API_sync_status_rep struct {
}

type API_account_balance_rep struct {
	Address string
	Balance map[string]uint64
}
