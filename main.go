package main

import (
	"encoding/hex"
	"flag"
	"fmt"

	devframework "github.com/0xkumi/incognito-dev-framework"
	"github.com/0xkumi/incognito-dev-framework/account"
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
		OTAKey := hex.EncodeToString(acc0.Keyset.OTAKey.GetOTASecretKey().ToBytesS())
		viewKey := hex.EncodeToString(acc0.Keyset.ReadonlyKey.Rk)
		importAccount("testacc", acc0.PaymentAddress, viewKey, OTAKey)
		node.Pause()
		node.SendPRV(node.GenesisAccount, acc0, 10000)
		for i := 0; i < 10; i++ {
			node.GenerateBlock().NextRound()
		}

		l, err := node.RPC.API_ListOutputCoins(acc0.PrivateKey, "")
		if err != nil {
			panic(err)
		}
		fmt.Println("len(l.Outputs)", len(l.Outputs))
		// for s, out := range l.Outputs {
		// 	fmt.Println("outs ", s, len(out))
		// 	for _, c := range out {
		// 		cBytes, _ := json.Marshal(c)
		// 		fmt.Println(string(cBytes))
		// 		cV2, err := jsonresult.NewCoinFromJsonOutCoin(c)
		// 		if err != nil {
		// 			panic(err)
		// 		}
		// 		cv2 := cV2.(*coin.CoinV2)
		// 		cv2Bytes := cv2.Bytes()
		// 		fmt.Println(hex.EncodeToString(cv2Bytes))

		// 		coinDecrypted, err := cv2.Decrypt(acc0.Keyset)
		// 		if err != nil {
		// 			panic(err)
		// 		}
		// 		// fmt.Println(string(coinDecrypted.GetKeyImage().MarshalText()))
		// 		coinDBytes, err := coinDecrypted.MarshalJSON()
		// 		if err != nil {
		// 			panic(err)
		// 		}
		// 		fmt.Println(coinDBytes)
		// 	}
		// }
		// node.ApplyChain(0).GenerateBlock().NextRound()
		node.Pause()
		return
	default:
		panic("unknown mode")
	}
	select {}
}
