package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/incognitochain/incognito-chain/privacy/key"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func startAPIService(port string) {
	http.HandleFunc("/importaccount", importAccountHandler)
	http.HandleFunc("/getcoinstodecrypt", getCoinsToDecryptHandler)
	http.HandleFunc("/submitkeyimages", submitKeyImages)
	http.HandleFunc("/daemonstate", getStateHandler)
	http.HandleFunc("/createtx", createTxHandler)
	http.HandleFunc("/cancelalltxs", cancelAllTxsHandler)
	http.HandleFunc("/getaccountlist", getAccountListHandler)
	http.HandleFunc("/removeaccount", removeAccountHandler)
	http.HandleFunc("/gettokenlist", getTokenListHandler)
	http.HandleFunc("/getbalance", getBalanceHandler)
	err := http.ListenAndServe("127.0.0.1:"+port, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func getStateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func removeAccountHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func getCoinsToDecryptHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	accName := r.URL.Query().Get("account")
	accountListLck.RLock()
	defer accountListLck.RUnlock()
	if _, ok := accountList[accName]; !ok {
		http.Error(w, "account name isn't exist", http.StatusBadRequest)
		return
	}
	if !accountList[accName].isReady {
		http.Error(w, "account not ready", http.StatusBadRequest)
		return
	}
	accState := accountList[accName]
	accState.lock.RLock()
	defer accState.lock.RUnlock()
	encryptCoins := make(map[string]map[string][]byte)
	for tokenID, coinsPubkey := range accState.EncryptedCoins {
		fmt.Println("len(coinsPubkey)", len(coinsPubkey))
		coins, err := getCoins(accState.Account.PAstr, tokenID, coinsPubkey)
		if err != nil {
			http.Error(w, "Unexpected error", http.StatusInternalServerError)
			return
		}
		otakey := &key.OTAKey{}
		otakey.SetOTASecretKey(accState.Account.OTAKey)
		encryptCoins[tokenID], err = ExtractCoinEncryptKeyImgData(coins, otakey)
		if err != nil {
			panic(err)
		}
	}

	coinsBytes, err := json.Marshal(encryptCoins)
	if err != nil {
		http.Error(w, "Unexpected error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(200)
	_, err = w.Write(coinsBytes)
	if err != nil {
		panic(err)
	}
	return
}

func cancelAllTxsHandler(w http.ResponseWriter, r *http.Request) {

	return
}

func createTxHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	_ = conn
}

func getAccountListHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	list, err := json.Marshal(getAccountList())
	if err != nil {
		http.Error(w, "Unexpected error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(200)
	_, err = w.Write(list)
	if err != nil {
		panic(err)
	}
}

func getTokenListHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func submitKeyImages(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

}

func getBalanceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	accName := r.URL.Query().Get("account")
	accountListLck.RLock()
	defer accountListLck.RUnlock()
	accountState, ok := accountList[accName]
	if !ok {
		http.Error(w, "account name isn't exist", http.StatusBadRequest)
		return
	}
	if !accountState.isReady {
		http.Error(w, "account not ready", http.StatusBadRequest)
		return
	}
	var rep API_account_balance_rep
	rep.Address = accountState.Account.PAstr
	rep.Balance = accountState.Balance

	result, _ := json.Marshal(rep)
	w.WriteHeader(200)
	_, err := w.Write(result)
	if err != nil {
		panic(err)
	}
}
