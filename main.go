package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	devframework "github.com/0xkumi/incognito-dev-framework"
	"github.com/0xkumi/incognito-dev-framework/account"
)

const (
	MODELIGHT = "light"
	MODERPC   = "rpc"
	MODESIM   = "sim"
)

var NODEMODE = ""
var debugNode *devframework.NodeEngine

func main() {
	modeFlag := flag.String("mode", "light", "daemon mode")
	rpcFlag := flag.String("rpchost", "http://127.0.0.1:9334", "rpc host")
	flag.Parse()
	err := initcoinDB("node")
	if err != nil {
		panic(err)
	}
	err = initAccountDB("node")
	if err != nil {
		panic(err)
	}
	err = initKeyimageDB("node")
	if err != nil {
		panic(err)
	}
	if err := initAccountService(); err != nil {
		panic(err)
	}
	go startAPIService("9000")
	NODEMODE = *modeFlag
	onGoingTxs = make(map[int]*txCreationInstance)
	switch *modeFlag {
	case MODELIGHT:
		node := devframework.NewAppNode("fullnode", devframework.TestNet2Param, true, false)
		localnode = node
		rpcnode = node.GetRPC()
		initCoinService()
	case MODERPC:
		node := devframework.NewRPCClient(*rpcFlag)
		rpcnode = node
		fmt.Println("started daemon in rpc mode...")
	case MODESIM:
		node := devframework.NewStandaloneSimulation("simnode", devframework.Config{
			ChainParam: devframework.NewChainParam(devframework.ID_TESTNET2).SetActiveShardNumber(8),
			DisableLog: true,
		})
		debugNode = node
		localnode = node
		rpcnode = node.GetRPC()
		// initCoinService()
		node.GenerateBlock().NextRound()

		node.ShowBalance(node.GenesisAccount)
		acc0, _ := account.NewAccountFromPrivatekey("111111bgk2j6vZQvzq8tkonDLLXEvLkMwBMn5BoLXLpf631boJnPDGEQMGvA1pRfT71Crr7MM2ShvpkxCBWBL2icG22cXSpcKybKCQmaxa")
		// acc1, _ := account.GenerateAccountByShard(0, 3, "abc")
		fmt.Println("acc0.PaymentAddress", acc0.PaymentAddress)
		OTAKey := hex.EncodeToString(acc0.Keyset.OTAKey.GetOTASecretKey().ToBytesS())
		viewKey := hex.EncodeToString(acc0.Keyset.ReadonlyKey.Rk)
		importAccount("testacc", acc0.PaymentAddress, viewKey, OTAKey)

		node.Pause()
		node.SendPRV(node.GenesisAccount, acc0, 2750000000000)
		for i := 0; i < 10; i++ {
			node.GenerateBlock().NextRound()
		}

		node.SendPRV(acc0, node.GenesisAccount, 6786)
		time.Sleep(10 * time.Second)
		r, err := node.GetRPC().API_SendTxCreateCustomToken(node.GenesisAccount.PrivateKey, acc0.PaymentAddress, true, "LamToken", "LAM", 600000000)
		if err != nil {
			panic(err)
		}
		fmt.Println("r.TokenID", r.TokenID)
		for i := 0; i < 10; i++ {
			node.GenerateBlock().NextRound()
		}

		time.Sleep(20 * time.Second)
		r1, err := node.GetRPC().API_SendTxCustomToken(acc0.PrivateKey, r.TokenID, map[string]uint64{
			node.GenesisAccount.PaymentAddress: 20000,
		}, 8, true)
		if err != nil {
			panic(err)
		}
		fmt.Println("r1.TxID", r1.TxID)
		// node.SendPRV(node.GenesisAccount, acc0, 30000)
		for i := 0; i < 10; i++ {
			node.GenerateBlock().NextRound()
		}
		// node.SendPRV(acc0, acc1, 6786)
		// node.SendPRV(node.GenesisAccount, acc0, 70000)
		// for i := 0; i < 4; i++ {
		// 	node.GenerateBlock().NextRound()
		// }

		// time.Sleep(20 * time.Second)
		// node.SendPRV(acc0, acc1, 6786)
		// for i := 0; i < 10; i++ {
		// 	node.GenerateBlock().NextRound()
		// }

		time.Sleep(20 * time.Second)
		// keyimages, err := getEncryptKeyImages("testacc")
		// if err != nil {
		// 	panic(err)
		// }

		// testkms := make(map[string]map[string]string)
		// for tokenID, coinList := range keyimages {
		// 	testkms[tokenID] = make(map[string]string)
		// 	for coinPk, km := range coinList {
		// 		h, _ := hex.DecodeString(km)
		// 		pk, _ := hex.DecodeString(coinPk)
		// 		Hp := operation.HashToPoint(pk)
		// 		K := new(operation.Scalar).FromBytesS(acc0.Keyset.PrivateKey)
		// 		s := operation.Scalar{}
		// 		H := s.FromBytesS(h)
		// 		k := new(operation.Scalar).Add(H, K)
		// 		img := new(operation.Point).ScalarMult(Hp, k)
		// 		testkms[tokenID][coinPk] = hex.EncodeToString(img.ToBytesS())
		// 	}
		// }
		// for tokenID, kms := range testkms {
		// 	e := submitKeyimages(tokenID, "testacc", kms)
		// 	if e != nil {
		// 		panic(e)
		// 	}
		// 	fmt.Println("e", e)
		// 	fmt.Println("tokenID", tokenID, "len(kms)", len(kms))
		// }

		// // node.Pause()
		// time.Sleep(5 * time.Second)
		// var paymentInfos []*privacy.PaymentInfo
		// paymentInfos = append(paymentInfos, &privacy.PaymentInfo{
		// 	PaymentAddress: acc1.Keyset.PaymentAddress,
		// 	Amount:         4321,
		// })
		// tx, err := CreateTxPRV(accountList["testacc"], common.PRVCoinID.String(), paymentInfos, nil, acc0.Keyset)
		// if err != nil {
		// 	panic(err)
		// }
		// txBytes, err := json.Marshal(tx)
		// txString := base58.Base58Check{}.Encode(txBytes, common.Base58Version)
		// fmt.Println("tx", txString)
		// node.InjectTx(txString)
		// for i := 0; i < 10; i++ {
		// 	node.GenerateBlock().NextRound()
		// }
		// node.ShowBalance(acc0)
		node.Pause()

		return
	default:
		panic("unknown mode")
	}
	select {}
}

func getEncryptKeyImages(accountName string) (map[string]map[string]string, error) {
	result := make(map[string]map[string]string)
	resp, err := http.Get("http://127.0.0.1:9000/getcoinstodecrypt?account=" + accountName)
	if err != nil {
		log.Fatalln(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func submitKeyimages(tokenID string, account string, kms map[string]string) error {
	var reqBody struct {
		Account   string
		Keyimages map[string]map[string]string
	}
	reqKms := make(map[string]map[string]string)
	for coinpub, km := range kms {
		if _, ok := reqKms[tokenID]; !ok {
			reqKms[tokenID] = make(map[string]string)
		}
		reqKms[tokenID][coinpub] = km
	}
	reqBody.Account = account
	reqBody.Keyimages = reqKms

	reqBytes, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", "http://127.0.0.1:9000/submitkeyimages", bytes.NewBuffer(reqBytes))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))
	return nil
}
