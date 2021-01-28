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
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/privacy/coin"
	"github.com/incognitochain/incognito-chain/rpcserver/jsonresult"
)

const (
	MODELIGHT = "light"
	MODERPC   = "rpc"
	MODESIM   = "sim"
)

var NODEMODE = ""

func main() {
	modeFlag := flag.String("mode", "light", "daemon mode")
	rpcFlag := flag.String("rpchost", "127.0.0.1:9334", "rpc host")
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
	switch *modeFlag {
	case MODELIGHT:
		node := devframework.NewAppNode("fullnode", devframework.TestNet2Param, true, false)
		localnode = node
		rpcnode = node.GetRPC()
		initCoinService()
	case MODERPC:
		node := devframework.NewRPCClient(*rpcFlag)
		rpcnode = node
	case MODESIM:
		node := devframework.NewStandaloneSimulation("simnode", devframework.Config{
			ChainParam: devframework.NewChainParam(devframework.ID_TESTNET2).SetActiveShardNumber(8),
			DisableLog: true,
		})
		localnode = node
		rpcnode = node.GetRPC()
		node.GenerateBlock().NextRound()

		node.ShowBalance(node.GenesisAccount)
		acc0, _ := account.NewAccountFromPrivatekey("111111bgk2j6vZQvzq8tkonDLLXEvLkMwBMn5BoLXLpf631boJnPDGEQMGvA1pRfT71Crr7MM2ShvpkxCBWBL2icG22cXSpB8A2XKuezTJ")
		acc1, _ := account.NewAccountFromPrivatekey("112t8rnZCyrvapkNCFFBKEpesfDMK8oyfW9eewDDJkF9UkqUk1NTSoYFQJXaBhmBBdboLEaDmufLJTSZ71ZpaWeAH9k4Jny5DVCfvCJbZL7k")

		OTAKey := hex.EncodeToString(acc0.Keyset.OTAKey.GetOTASecretKey().ToBytesS())
		viewKey := hex.EncodeToString(acc0.Keyset.ReadonlyKey.Rk)
		importAccount("testacc", acc0.PaymentAddress, viewKey, OTAKey)
		node.Pause()
		node.SendPRV(node.GenesisAccount, acc0, 10000)
		for i := 0; i < 10; i++ {
			node.GenerateBlock().NextRound()
		}
		node.SendPRV(node.GenesisAccount, acc0, 30000)
		for i := 0; i < 4; i++ {
			node.GenerateBlock().NextRound()
		}
		node.SendPRV(acc0, acc1, 6786)
		node.SendPRV(node.GenesisAccount, acc0, 70000)
		for i := 0; i < 4; i++ {
			node.GenerateBlock().NextRound()
		}

		time.Sleep(20 * time.Second)

		node.SendPRV(acc0, acc1, 6786)
		for i := 0; i < 10; i++ {
			node.GenerateBlock().NextRound()
		}

		time.Sleep(20 * time.Second)
		l, err := node.RPC.API_ListOutputCoins(acc0.PrivateKey, common.PRVCoinID.String())
		if err != nil {
			panic(err)
		}
		// fmt.Println("len(l.Outputs)", len(l.Outputs))
		testkms := make(map[string]string)
		for _, out := range l.Outputs {
			fmt.Println("len(out) ", len(out))
			for _, c := range out {
				// cBytes, _ := json.Marshal(c)
				// fmt.Println(string(cBytes))
				cV2, err := jsonresult.NewCoinFromJsonOutCoin(c)
				if err != nil {
					panic(err)
				}
				cv2 := cV2.(*coin.CoinV2)
				acc01, _ := account.NewAccountFromPrivatekey("111111bgk2j6vZQvzq8tkonDLLXEvLkMwBMn5BoLXLpf631boJnPDGEQMGvA1pRfT71Crr7MM2ShvpkxCBWBL2icG22cXSpB8A2XKuezTJ")
				coinDecrypted, err := cv2.Decrypt(acc01.Keyset)
				if err != nil {
					panic(err)
				}
				cv2Bytes := cv2.GetPublicKey().ToBytesS()
				fmt.Println("hex.EncodeToString(cv2Bytes)", hex.EncodeToString(cv2Bytes))
				fmt.Println("value/keyimage", cv2.GetValue(), hex.EncodeToString(coinDecrypted.GetKeyImage().ToBytesS()))
				testkms[hex.EncodeToString(cv2.GetPublicKey().ToBytesS())] = hex.EncodeToString(coinDecrypted.GetKeyImage().ToBytesS())
			}
		}
		r, _ := getEncryptKeyImages("testacc")
		fmt.Println("r", r)

		e := submitKeyimages(common.PRVCoinID.String(), "testacc", testkms)
		if err != nil {
			panic(e)
		}
		fmt.Println("e", e)
		// node.ApplyChain(0).GenerateBlock().NextRound()
		node.Pause()
		return
	default:
		panic("unknown mode")
	}
	select {}
}

func getEncryptKeyImages(accountName string) (map[string]map[string][]byte, error) {
	result := make(map[string]map[string][]byte)
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
	req.Header.Set("X-Custom-Header", "myvalue")
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
