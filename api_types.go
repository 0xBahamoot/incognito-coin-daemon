package main

type API_create_tx_req struct {
	Account    string      `json:"account"`
	PrivateKey string      `json:"privatekey"`
	TxType     string      `json:"type"`
	TxParams   interface{} `json:"params"`
}

type API_submit_keyimages_req struct {
	Account   string
	Keyimages map[string]map[string]string
}

type API_sync_status_rep struct {
}

type API_account_balance_rep struct {
	Address string
	Balance map[string]uint64
}
