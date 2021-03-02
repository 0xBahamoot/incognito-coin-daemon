package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/incognitochain/incognito-chain/blockchain"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/dataaccessobject/statedb"
	"github.com/incognitochain/incognito-chain/incognitokey"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/privacy/key"
	"github.com/incognitochain/incognito-chain/rpcserver/bean"
	"github.com/incognitochain/incognito-chain/transaction"
	"github.com/incognitochain/incognito-chain/transaction/tx_generic"
	"github.com/incognitochain/incognito-chain/transaction/tx_ver2"
	"github.com/incognitochain/incognito-chain/transaction/utils"
	"github.com/incognitochain/incognito-chain/wallet"
)

var pendingTx []string
var pendingTxCoins map[string][]string

type txCreationInstance struct {
	TxCID         int
	Type          int
	AccountState  *AccountState
	PrivateKeyset *incognitokey.KeySet
	ViaLedger     bool
	TxParamsRaw   interface{}
	wsConn        *websocket.Conn
	respondWaitor *chan []byte //only 1 respond waitor
	quitCh        chan struct{}
}

var onGoingTxs map[int]*txCreationInstance
var onGoingTxsLck sync.Mutex

func CreateTx(req *API_create_tx_req, wsConn *websocket.Conn) {
	onGoingTxsLck.Lock()
	accountListLck.RLock()
	txCID := len(onGoingTxs)
	var txType int
	switch req.TxType {
	case "transfer_prv":
		txType = TXTRANFER_PRV
	case "transfer_token":
		txType = TXTRANFER_TOKEN
	case "staking":
		txType = TXSTAKING
	case "stopstaking":
		txType = TXSTOPSTAKING
	case "trade":
		txType = TXTRADE
	case "trade_token":
		txType = TXTRADE_TOKEN
	case "tradecross":
		txType = TXTRADE_CROSSPOOL
	case "tradecross_token":
		txType = TXTRADE_CROSSPOOL_TOKEN
	case "contribution":
		txType = TXCONTRIBUTION
	case "contribution_token":
		txType = TXCONTRIBUTION_TOKEN
	case "withdrawReward":
		txType = TXWITHDRAW_REWARD
	default:
		wsConn.Close()
		log.Println(errors.New("unsupported tx type"))
		return
	}
	var viaLedger bool
	var ks *incognitokey.KeySet
	if req.PrivateKey != "" {
		wl, err := wallet.Base58CheckDeserialize(req.PrivateKey)
		if err != nil {
			wsConn.Close()
			log.Println(err)
			return
		}
		viaLedger = true
		ks = &wl.KeySet
	}
	newInstance := txCreationInstance{
		TxCID:         txCID,
		Type:          txType,
		ViaLedger:     viaLedger,
		PrivateKeyset: ks,
		AccountState:  accountList[req.Account],
		TxParamsRaw:   req.TxParams,
		wsConn:        wsConn,
		quitCh:        make(chan struct{}),
	}

	onGoingTxs[txCID] = &newInstance
	accountListLck.RUnlock()
	onGoingTxsLck.Unlock()

	go newInstance.Start()

	for {
		select {
		case <-newInstance.quitCh:
			wsConn.Close()
			return
		default:
			_, message, err := wsConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("error: %v", err)
				}
				break
			}
			if newInstance.respondWaitor != nil {
				*newInstance.respondWaitor <- message
			}
		}

	}
}

func completeTx(txCID int) {
	onGoingTxsLck.Lock()
	onGoingTxs[txCID].quitCh <- struct{}{}
	delete(onGoingTxs, txCID)
	onGoingTxsLck.Unlock()
}

func (inst *txCreationInstance) Start() {
	var tx metadata.Transaction
	var txerr error
	switch inst.Type {
	case TXTRANFER_PRV:
		txParams, err := extractRawTxParam(inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		fmt.Println("extractRawTxParam success")
		tx, txerr = createTxPRV(inst, txParams, nil, inst.PrivateKeyset)
	case TXTRANFER_TOKEN:
		txParams, err := extractRawTxTokenParam(inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		tx, txerr = createTxToken(inst, txParams, nil, inst.PrivateKeyset)
	case TXSTAKING:
		txParams, err := extractRawTxParam(inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		metadata, err := NewStakingMetadata(inst.AccountState.Account, inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		tx, txerr = createTxPRV(inst, txParams, metadata, inst.PrivateKeyset)
	case TXSTOPSTAKING:
		txParams, err := extractRawTxParam(inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		metadata, err := NewStopAutoStakingMetadata(inst.AccountState.Account, inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		tx, txerr = createTxPRV(inst, txParams, metadata, inst.PrivateKeyset)
	case TXTRADE:
		metadata, err := NewPDETradeRequest(inst.AccountState.Account, inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		_ = metadata
	case TXTRADE_TOKEN:
		metadata, err := NewPDETradeRequest(inst.AccountState.Account, inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		_ = metadata
	case TXTRADE_CROSSPOOL:
		metadata, err := NewPDECrossPoolTradeRequest(inst.AccountState.Account, inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		_ = metadata
	case TXTRADE_CROSSPOOL_TOKEN:
		metadata, err := NewPDECrossPoolTradeRequest(inst.AccountState.Account, inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		_ = metadata
	case TXCONTRIBUTION:
		metadata, err := NewPDEContribution(inst.AccountState.Account, inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		_ = metadata
	case TXCONTRIBUTION_TOKEN:
		metadata, err := NewPDEContribution(inst.AccountState.Account, inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		_ = metadata
	case TXWITHDRAW_REWARD:
		metadata, err := NewWithdrawRewardRequest(inst.AccountState.Account, inst.TxParamsRaw)
		if err != nil {
			panic(err)
		}
		_ = metadata
	}
	request := LedgerRequest{
		Cmd: "result",
	}
	if txerr != nil {
		request.Data = []byte(txerr.Error())
		panic(txerr)
	} else {
		request.Data = tx.Hash().Bytes()
		// go func(tx1 metadata.Transaction) {

		// 	fmt.Println("tx", txString)
		// 	err := debugNode.InjectTx(txString, false)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	for i := 0; i < 10; i++ {
		// 		debugNode.GenerateBlock().NextRound()
		// 	}
		// 	fmt.Println("debugNode.InjectTx success")
		// }(tx)

		// go func(tx1 metadata.Transaction) {
		// 	txBytes, _ := json.Marshal(tx)
		// 	txString := base58.Base58Check{}.Encode(txBytes, common.Base58Version)
		// 	result, err := rpcnode.API_SendRawTransaction(txString)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	fmt.Println("txresult", result)
		// }(tx)
	}
	requestBytes, _ := json.Marshal(request)
	err := inst.sendMsgToClient(requestBytes)
	if err != nil {
		panic(err)
	}

	completeTx(inst.TxCID)
}

func (inst *txCreationInstance) sendMsgToClient(req []byte) error {
	writeWait := 5 * time.Second
	_ = inst.wsConn.SetWriteDeadline(time.Now().Add(writeWait))

	w, err := inst.wsConn.NextWriter(websocket.TextMessage)
	if err != nil {
		log.Println(err)
		return err
	}
	if _, err := w.Write(req); err != nil {
		log.Println(err)
		return err
	}

	if err := w.Close(); err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func createTxPRV(instance *txCreationInstance, txParams *bean.CreateRawTxParam, metadataParam metadata.Metadata, debugKeyset *incognitokey.KeySet) (metadata.Transaction, error) {
	//create tx param
	txParams.SenderKeySet = debugKeyset
	txParams.ShardIDSender = instance.AccountState.Account.ShardID

	var stateDB *statedb.StateDB
	if NODEMODE == MODESIM {
		stateDB = localnode.GetBlockchain().GetBestStateShard(instance.AccountState.Account.ShardID).GetCopiedTransactionStateDB()
	} else {
		stateDB = TransactionStateDB[instance.AccountState.Account.ShardID]
	}
	tx, err := buildRawTransaction(instance, txParams, metadataParam, stateDB)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func createTxToken(instance *txCreationInstance, txParams *bean.CreateRawPrivacyTokenTxParam, metadataParam metadata.Metadata, debugKeyset *incognitokey.KeySet) (metadata.Transaction, error) {
	//create tx param
	txParams.SenderKeySet = debugKeyset
	txParams.ShardIDSender = instance.AccountState.Account.ShardID

	var stateDB *statedb.StateDB
	if NODEMODE == MODESIM {
		stateDB = localnode.GetBlockchain().GetBestStateShard(instance.AccountState.Account.ShardID).GetCopiedTransactionStateDB()
	} else {
		stateDB = TransactionStateDB[instance.AccountState.Account.ShardID]
	}

	tx, err := buildRawTransactionToken(instance, txParams, metadataParam, stateDB)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func buildRawTransactionToken(instance *txCreationInstance, txParam *bean.CreateRawPrivacyTokenTxParam, metaData metadata.Metadata, stateDB *statedb.StateDB) (metadata.Transaction, error) {
	// BuildRawPrivacyCustomTokenTransaction
	// BuildTokenParam
	// BuildPrivacyCustomTokenParam
	tokenParams, _, _, err := BuildPrivacyCustomTokenParam(instance.AccountState, txParam.TokenParamsRaw, instance.PrivateKeyset, instance.AccountState.Account.ShardID, metaData)
	if err != nil {
		return nil, err
	}
	inputCoins, realFeePRV, err := chooseCoinsToSpendForAccount(instance.AccountState, "", txParam.PaymentInfos, metaData, nil)
	if err != nil {
		return nil, err
	}
	if len(inputCoins) > 8 {
		return nil, errors.New("inputCoins exceed 8")
	}
	initializingParams := transaction.NewTxTokenParams(&txParam.SenderKeySet.PrivateKey,
		txParam.PaymentInfos,
		inputCoins,
		realFeePRV,
		tokenParams,
		stateDB,
		metaData,
		txParam.HasPrivacyCoin,
		txParam.HasPrivacyToken,
		txParam.ShardIDSender, txParam.Info,
		nil)

	//
	//Tx Init Start
	//
	txPrivacyParams := tx_generic.NewTxPrivacyInitParams(
		initializingParams.SenderKey,
		initializingParams.PaymentInfo,
		initializingParams.InputCoin,
		initializingParams.FeeNativeCoin,
		initializingParams.HasPrivacyCoin,
		initializingParams.TransactionStateDB,
		nil,
		initializingParams.MetaData,
		initializingParams.Info,
	)
	if err := tx_generic.ValidateTxParams(txPrivacyParams); err != nil {
		return nil, err
	}
	// we use tx ver 2 only
	var txToken tx_ver2.TxToken
	txBase := new(tx_ver2.Tx)
	if err := initializeTxAndParams(instance.AccountState.Account, &txBase.TxBase, txPrivacyParams); err != nil {
		return nil, err
	}

	// check this IsNonPrivacyNonInput
	if len(txPrivacyParams.InputCoins) == 0 && txPrivacyParams.Fee == 0 && !txPrivacyParams.HasPrivacy {
		if txPrivacyParams.SenderSK != nil {
			if txToken.Tx.Sig, txToken.Tx.SigPubKey, err = signSchnorrHost(txPrivacyParams.SenderSK, txBase.Hash()[:], false); err != nil {
				return nil, err
			}
		} else {
			if txToken.Tx.Sig, txToken.Tx.SigPubKey, err = signSchnorrLedger(instance, txBase.Hash()[:], false); err != nil {
				return nil, err
			}
		}

		err = txToken.SetTxBase(txBase)
		if err != nil {
			return nil, err
		}
		return &txToken, nil
	}

	// check tx size
	limitFee := uint64(0)
	estimateTxSizeParam := tx_generic.NewEstimateTxSizeParam(2, len(initializingParams.InputCoin), len(initializingParams.PaymentInfo),
		initializingParams.HasPrivacyCoin, nil, initializingParams.TokenParams, limitFee)
	if txSize := tx_generic.EstimateTxSize(estimateTxSizeParam); txSize > common.MaxTxSize {
		return nil, errors.New("Tx exceed max size")
	}

	// Init PRV Fee
	txBase.SetType(common.TxCustomTokenPrivacyType)
	ins, outs, err := proveTxPRV(instance, txBase, txPrivacyParams)
	if err != nil {
		return nil, err
	}

	txn := makeTxToken(txBase, nil, nil, nil)
	// Init, prove and sign(CA) Token
	if err := initToken(instance, &txToken, txn, initializingParams); err != nil {
		return nil, err
	}
	tdh, err := txToken.TokenData.Hash()
	if err != nil {
		return nil, err
	}
	message := common.HashH(append(txBase.Hash()[:], tdh[:]...))

	err = signOnMessage(instance, txBase, ins, outs, txPrivacyParams, message[:])
	if err != nil {
		return nil, err
	}
	err = txToken.SetTxBase(txBase)
	if err != nil {
		return nil, err
	}
	//validate tx param ValidateTxParams
	txSize := txToken.GetTxActualSize()
	if txSize > common.MaxTxSize {
		return nil, errors.New("Tx exceed max size")
	}
	return &txToken, nil
}

func buildRawTransaction(instance *txCreationInstance, params *bean.CreateRawTxParam, meta metadata.Metadata, stateDB *statedb.StateDB) (metadata.Transaction, error) {
	// get output coins to spend and real fee
	inputCoins, realFee, err := chooseCoinsToSpendForAccount(instance.AccountState, "", params.PaymentInfos, meta, nil)
	if err != nil {
		return nil, err
	}

	// rewrite TxBase InitializeTxAndParams
	var senderSK *key.PrivateKey
	senderSK = nil
	if params.SenderKeySet != nil {
		senderSK = &params.SenderKeySet.PrivateKey
	}
	initializingParams := tx_generic.NewTxPrivacyInitParams(senderSK,
		params.PaymentInfos, inputCoins,
		realFee, true,
		stateDB,
		nil, // &common.PRVCoinID,
		meta,
		[]byte{},
	)
	//
	//Tx Init Start
	//
	if err := tx_generic.ValidateTxParams(initializingParams); err != nil {
		return nil, err
	}
	// we use tx ver 2 only
	var tx tx_ver2.Tx
	if err := initializeTxAndParams(instance.AccountState.Account, &tx.TxBase, initializingParams); err != nil {
		return nil, err
	}
	// check this IsNonPrivacyNonInput
	if len(initializingParams.InputCoins) == 0 && initializingParams.Fee == 0 && !initializingParams.HasPrivacy {
		if initializingParams.SenderSK != nil {
			if tx.Sig, tx.SigPubKey, err = signSchnorrHost(initializingParams.SenderSK, tx.Hash()[:], false); err != nil {
				return nil, err
			}
		} else {
			if tx.Sig, tx.SigPubKey, err = signSchnorrLedger(instance, tx.Hash()[:], false); err != nil {
				return nil, err
			}
		}
		return &tx, nil
	}

	// proveTxPRV
	// coins conceal here too
	ins, outs, err := proveTxPRV(instance, &tx, initializingParams)
	if err != nil {
		return nil, err
	}

	// ringSig + mlsag
	err = signOnMessage(instance, &tx, ins, outs, initializingParams, tx.Hash()[:])
	if err != nil {
		return nil, err
	}
	//validate tx param ValidateTxParams
	txSize := tx.GetTxActualSize()
	if txSize > common.MaxTxSize {
		return nil, errors.New("Tx exceed max size")
	}
	return &tx, nil
}

// use for prv tx
func proveTxPRV(instance *txCreationInstance, tx *tx_ver2.Tx, params *tx_generic.TxPrivacyInitParams) ([]privacy.PlainCoin, []*privacy.CoinV2, error) {
	outputCoins, err := NewCoinV2ArrayFromPaymentInfoArray(params.PaymentInfo, params.TokenID)
	if err != nil {
		fmt.Printf("Cannot parse outputCoinV2 to outputCoins, error %v \n", err)
		return nil, nil, err
	}

	inputCoins := params.InputCoins

	// gen tx proof
	tx.Proof, err = privacy.ProveV2(inputCoins, outputCoins, nil, false, params.PaymentInfo)
	if err != nil {
		return nil, nil, err
	}

	if tx.ShouldSignMetaData() {
		if err := signMetadata(instance, tx, params.SenderSK); err != nil {
			panic(err)
		}
	}

	return inputCoins, outputCoins, nil
}

func proveTxToken(instance *txCreationInstance, tx *tx_ver2.Tx, params *tx_generic.TxPrivacyInitParams) (bool, error) {
	if err := tx_generic.ValidateTxParams(params); err != nil {
		return false, err
	}

	// Init tx and params (tx and params will be changed)
	fmt.Printf("init token with receivers : %v", params.PaymentInfo)
	if err := tx.InitializeTxAndParams(params); err != nil {
		return false, err
	}
	tx.SetType(common.TxCustomTokenPrivacyType)
	isBurning, err := proveCA(instance, params, tx)
	if err != nil {
		return false, err
	}
	return isBurning, nil
}

func proveCA(instance *txCreationInstance, params *tx_generic.TxPrivacyInitParams, tx *tx_ver2.Tx) (bool, error) {
	var err error
	var outputCoins []*privacy.CoinV2
	var sharedSecrets []*privacy.Point
	// fmt.Printf("tokenID is %v\n",params.TokenID)
	var numOfCoinsBurned uint = 0
	var isBurning bool = false
	for _, inf := range params.PaymentInfo {
		c, ss, err := createUniqueOTACoinCA(inf, params.TokenID)
		if err != nil {
			utils.Logger.Log.Errorf("Cannot parse outputCoinV2 to outputCoins, error %v ", err)
			return false, err
		}
		// the only way err!=nil but ss==nil is a coin meant for burning address
		if ss == nil {
			isBurning = true
			numOfCoinsBurned += 1
		}
		sharedSecrets = append(sharedSecrets, ss)
		outputCoins = append(outputCoins, c)
	}
	// first, reject the invalid case. After this, isBurning will correctly determine if TX is burning
	if numOfCoinsBurned > 1 {
		utils.Logger.Log.Errorf("Cannot burn multiple coins")
		return false, utils.NewTransactionErr(utils.UnexpectedError, errors.New("output must not have more than 1 burned coin"))
	}
	// outputCoins, err := newCoinV2ArrayFromPaymentInfoArray(params.PaymentInfo, params.TokenID, params.StateDB)

	// inputCoins is plainCoin because it may have coinV1 with coinV2
	inputCoins := params.InputCoins
	tx.Proof, err = privacy.ProveV2(inputCoins, outputCoins, sharedSecrets, true, params.PaymentInfo)
	if err != nil {
		utils.Logger.Log.Errorf("Error in privacy_v2.Prove, error %v ", err)
		return false, err
	}

	if tx.ShouldSignMetaData() {
		if err := signMetadata(instance, tx, params.SenderSK); err != nil {
			utils.Logger.Log.Error("Cannot signOnMessage txMetadata in shouldSignMetadata")
			return false, err
		}
	}
	//signOnMessage
	err = signCA(instance, tx, inputCoins, outputCoins, sharedSecrets, params, tx.Hash()[:])
	return isBurning, err
}
func signCA(instance *txCreationInstance, tx *tx_ver2.Tx, inp []privacy.PlainCoin, out []*privacy.CoinV2, outputSharedSecrets []*privacy.Point, params *tx_generic.TxPrivacyInitParams, hashedMessage []byte) error {
	if tx.Sig != nil {
		return utils.NewTransactionErr(utils.UnexpectedError, errors.New("input transaction must be an unsigned one"))
	}
	ringSize := privacy.RingSize

	// Generate Ring
	piBig, piErr := common.RandBigIntMaxRange(big.NewInt(int64(ringSize)))
	if piErr != nil {
		return piErr
	}
	var pi int = int(piBig.Int64())
	shardID := common.GetShardIDFromLastByte(tx.PubKeyLastByteSender)
	ring, indexes, commitmentsToZero, err := generateMlsagRingWithIndexesCA(inp, out, params, pi, shardID, ringSize)
	if err != nil {
		utils.Logger.Log.Errorf("generateMlsagRingWithIndexes got error %v ", err)
		return err
	}

	// Set SigPubKey
	txSigPubKey := new(tx_ver2.SigPubKey)
	txSigPubKey.Indexes = indexes
	tx.SigPubKey, err = txSigPubKey.Bytes()
	if err != nil {
		utils.Logger.Log.Errorf("tx.SigPubKey cannot parse from Bytes, error %v ", err)
		return err
	}

	// Set sigPrivKey
	err = createMlsagSigCAHost(ring, pi, hashedMessage, inp, out, outputSharedSecrets, params, shardID, commitmentsToZero, tx)
	if err != nil {
		utils.Logger.Log.Errorf("Cannot create private key of mlsag: %v", err)
		return err
	}

	return err
}

func signMetadata(instance *txCreationInstance, tx *tx_ver2.Tx, debugPrivKey *privacy.PrivateKey) error {
	metaSig := tx.Metadata.GetSig()
	if metaSig != nil && len(metaSig) > 0 {
		return errors.New("meta.Sig should be empty or nil")
	}
	data := tx.HashWithoutMetadataSig()[:]
	var signature []byte
	var err error
	if debugPrivKey != nil {
		if signature, _, err = signSchnorrHost(debugPrivKey, data, true); err != nil {
			return err
		}
	} else {
		if signature, _, err = signSchnorrLedger(instance, tx.Hash()[:], true); err != nil {
			return err
		}
	}
	tx.Metadata.SetSig(signature)
	fmt.Println("Signature Detail", tx.Metadata.GetSig())
	return nil
}

func initializeTxAndParams(account *Account, tx *tx_generic.TxBase, params *tx_generic.TxPrivacyInitParams) error {
	var err error
	// Tx: initialize some values
	if tx.LockTime == 0 {
		tx.LockTime = time.Now().Unix()
	}
	tx.Fee = params.Fee
	tx.Type = common.TxNormalType
	tx.Metadata = params.MetaData

	tx.PubKeyLastByteSender = account.PaymentAddress.Pk[len(account.PaymentAddress.Pk)-1]
	//we use ver 2 only
	tx.Version = 2
	if tx.Info, err = tx_generic.GetTxInfo(params.Info); err != nil {
		return err
	}

	// Params: update balance if overbalance
	if err = updateParamsWhenOverBalance(params, account.PaymentAddress); err != nil {
		return err
	}
	return nil
}

func updateParamsWhenOverBalance(params *tx_generic.TxPrivacyInitParams, senderPaymentAddress privacy.PaymentAddress) error {
	// Calculate sum of all output coins' value
	sumOutputValue := uint64(0)
	for _, p := range params.PaymentInfo {
		sumOutputValue += p.Amount
	}

	// Calculate sum of all input coins' value
	sumInputValue := uint64(0)
	for _, coin := range params.InputCoins {
		sumInputValue += coin.GetValue()
	}

	overBalance := int64(sumInputValue - sumOutputValue - params.Fee)
	// Check if sum of input coins' value is at least sum of output coins' value and tx fee
	if overBalance < 0 {
		return fmt.Errorf("Sum of inputs less than outputs: sumInputValue=%d sumOutputValue=%d fee=%d", sumInputValue, sumOutputValue, params.Fee)
	}
	// Create a new payment to sender's pk where amount is overBalance if > 0
	if overBalance > 0 {
		// Should not check error because have checked before
		changePaymentInfo := new(privacy.PaymentInfo)
		changePaymentInfo.Amount = uint64(overBalance)
		changePaymentInfo.PaymentAddress = senderPaymentAddress
		params.PaymentInfo = append(params.PaymentInfo, changePaymentInfo)
	}

	return nil
}

func signOnMessage(instance *txCreationInstance, tx *tx_ver2.Tx, inp []privacy.PlainCoin, out []*privacy.CoinV2, params *tx_generic.TxPrivacyInitParams, hashedMessage []byte) error {
	if tx.Sig != nil {
		return utils.NewTransactionErr(utils.UnexpectedError, errors.New("input transaction must be an unsigned one"))
	}
	ringSize := privacy.RingSize

	// Generate Ring
	piBig, piErr := common.RandBigIntMaxRange(big.NewInt(int64(ringSize)))
	if piErr != nil {
		return piErr
	}
	var pi int = int(piBig.Int64())
	shardID := common.GetShardIDFromLastByte(tx.PubKeyLastByteSender)
	ring, indexes, commitmentToZero, err := generateMlsagRingWithIndexes(inp, out, params, pi, shardID, ringSize)
	if err != nil {
		return err
	}

	// Set SigPubKey
	txSigPubKey := new(tx_ver2.SigPubKey)
	txSigPubKey.Indexes = indexes
	tx.SigPubKey, err = txSigPubKey.Bytes()
	if err != nil {
		return err
	}

	if params.SenderSK != nil {
		err := createMlsagSigHost(ring, pi, hashedMessage, inp, out, params.SenderSK, commitmentToZero, tx)
		if err != nil {
			return err
		}
		return err
	} else {
		err := createMlsagSigLedger(instance, ring, pi, hashedMessage, inp, out, params.SenderSK, commitmentToZero, tx)
		if err != nil {
			return err
		}
	}
	return nil
}

func extractRawTxParam(params interface{}) (*bean.CreateRawTxParam, error) {
	arrayParams := common.InterfaceSlice(params)
	if len(arrayParams) < 2 {
		return nil, errors.New("not enough param")
	}
	var ok bool
	receivers := make(map[string]interface{})
	if arrayParams[0] != nil {
		receivers, ok = arrayParams[0].(map[string]interface{})
		if !ok {
			return nil, errors.New("receivers param is invalid")
		}
	}
	paymentInfos := make([]*privacy.PaymentInfo, 0)
	for paymentAddressStr, amount := range receivers {
		keyWalletReceiver, err := wallet.Base58CheckDeserialize(paymentAddressStr)
		if err != nil {
			return nil, err
		}
		if len(keyWalletReceiver.KeySet.PaymentAddress.Pk) == 0 {
			return nil, fmt.Errorf("payment info %+v is invalid", paymentAddressStr)
		}

		amountParam, err := common.AssertAndConvertNumber(amount)
		if err != nil {
			return nil, err
		}

		paymentInfo := &privacy.PaymentInfo{
			Amount:         amountParam,
			PaymentAddress: keyWalletReceiver.KeySet.PaymentAddress,
		}
		paymentInfos = append(paymentInfos, paymentInfo)
	}
	estimateFeeCoinPerKb, ok := arrayParams[1].(float64)
	if !ok {
		return nil, errors.New("estimate fee coin per kb is invalid")
	}

	// hasPrivacyCoinParam := float64(-1)
	// if len(arrayParams) > 3 {
	// 	hasPrivacyCoinParam, ok = arrayParams[2].(float64)
	// 	if !ok {
	// 		return nil, errors.New("has privacy for tx is invalid")
	// 	}
	// }

	// param #3 arrayParams[2]: metadata | tokenparam (optional)
	// don't do anything

	info := []byte{}
	if len(arrayParams) > 4 {
		if arrayParams[4] != nil {
			infoStr, ok := arrayParams[4].(string)
			if !ok {
				return nil, errors.New("info is invalid")
			}
			info = []byte(infoStr)
		}
	}
	return &bean.CreateRawTxParam{
		PaymentInfos:         paymentInfos,
		EstimateFeeCoinPerKb: int64(estimateFeeCoinPerKb),
		HasPrivacyCoin:       true,
		Info:                 info,
	}, nil
}

func extractRawTxTokenParam(params interface{}) (*bean.CreateRawPrivacyTokenTxParam, error) {
	arrayParams := common.InterfaceSlice(params)
	if len(arrayParams) < 3 {
		return nil, errors.New("not enough param")
	}

	// create basic param for tx
	txparam, err := extractRawTxParam(params)
	if err != nil {
		return nil, err
	}

	// param #4: token component
	tokenParamsRaw, ok := arrayParams[3].(map[string]interface{})
	if !ok {
		return nil, errors.New("token param is invalid")
	}

	isGetPTokenFee := false
	if isGetPTokenFeeParam, ok := tokenParamsRaw["IsGetPTokenFee"].(bool); ok {
		isGetPTokenFee = isGetPTokenFeeParam
	}

	unitPTokenFee := int64(-1)
	if unitPTokenFeeParam, ok := tokenParamsRaw["UnitPTokenFee"].(float64); ok {
		unitPTokenFee = int64(unitPTokenFeeParam)
	}
	/****** END FEtch data from params *********/

	return &bean.CreateRawPrivacyTokenTxParam{
		SenderKeySet:         txparam.SenderKeySet,
		PaymentInfos:         txparam.PaymentInfos,
		EstimateFeeCoinPerKb: int64(txparam.EstimateFeeCoinPerKb),
		HasPrivacyCoin:       true,
		Info:                 txparam.Info,
		HasPrivacyToken:      true,
		TokenParamsRaw:       tokenParamsRaw,
		IsGetPTokenFee:       isGetPTokenFee,
		UnitPTokenFee:        unitPTokenFee,
	}, nil
}

func BuildPrivacyCustomTokenParam(accountState *AccountState, tokenParamsRaw map[string]interface{}, senderKeySet *incognitokey.KeySet, shardIDSender byte, metadataParam metadata.Metadata) (*transaction.TokenParam, map[common.Hash]transaction.TransactionToken, map[common.Hash]blockchain.CrossShardTokenPrivacyMetaData, error) {
	property, ok := tokenParamsRaw["TokenID"].(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("Invalid Token ID, Params %+v ", tokenParamsRaw)
	}
	_, ok = tokenParamsRaw["TokenReceivers"]
	if !ok {
		return nil, nil, nil, errors.New("Token Receiver is invalid")
	}
	tokenName, ok := tokenParamsRaw["TokenName"].(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("Invalid Token Name, Params %+v ", tokenParamsRaw)
	}
	tokenSymbol, ok := tokenParamsRaw["TokenSymbol"].(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("Invalid Token Symbol, Params %+v ", tokenParamsRaw)
	}
	tokenTxType, ok := tokenParamsRaw["TokenTxType"].(float64)
	if !ok {
		return nil, nil, nil, fmt.Errorf("Invalid Token Tx Type, Params %+v ", tokenParamsRaw)
	}
	tokenAmount, err := common.AssertAndConvertNumber(tokenParamsRaw["TokenAmount"])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Invalid Token Amout - error: %+v ", err)
	}

	tokenFee, err := common.AssertAndConvertNumber(tokenParamsRaw["TokenFee"])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Invalid Token Fee - error: %+v ", err)
	}

	if tokenTxType == transaction.CustomTokenInit {
		tokenFee = 0
	}
	tokenParams := &transaction.TokenParam{
		PropertyID:     property,
		PropertyName:   tokenName,
		PropertySymbol: tokenSymbol,
		TokenTxType:    int(tokenTxType),
		Amount:         uint64(tokenAmount),
		TokenInput:     nil,
		Fee:            uint64(tokenFee),
	}
	voutsAmount := int64(0)
	var err1 error

	tokenParams.Receiver, voutsAmount, err1 = CreateCustomTokenPrivacyReceiverArray(tokenParamsRaw["TokenReceivers"])
	if err1 != nil {
		return nil, nil, nil, err1
	}
	voutsAmount += int64(tokenFee)
	// get list custom token
	switch tokenParams.TokenTxType {
	case transaction.CustomTokenTransfer:
		{
			tokenID, err := common.Hash{}.NewHashFromStr(tokenParams.PropertyID)
			if err != nil {
				return nil, nil, nil, errors.New("Invalid Token ID")
			}
			// isExisted := statedb.PrivacyTokenIDExisted(txService.BlockChain.GetBestStateShard(shardIDSender).GetCopiedTransactionStateDB(), *tokenID)
			// if !isExisted {
			// 	var isBridgeToken bool

			// 	bridgeTokenInfos, err := rpcnode.API_GetAllBridgeTokens()
			// 	if err != nil {
			// 		return nil, nil, nil, errors.New("Invalid Token ID")
			// 	}
			// 	for _, bridgeToken := range allBridgeTokens {
			// 		if bridgeToken.TokenID.IsEqual(tokenID) {
			// 			isBridgeToken = true
			// 			break
			// 		}
			// 	}
			// 	if !isBridgeToken {
			// 		// totally invalid token
			// 		return nil, nil, nil, errors.New("Invalid Token ID")
			// 	}
			// 	//return nil, nil, nil, NewRPCError(BuildPrivacyTokenParamError, err)
			// }
			outputTokens, _, err := chooseCoinsToSpendForAccount(accountState, tokenID.String(), tokenParams.Receiver, metadataParam, tokenParams)
			if err != nil {
				return nil, nil, nil, err
			}
			tokenParams.TokenInput = outputTokens
		}
	case transaction.CustomTokenInit:
		{
			if len(tokenParams.Receiver) == 0 {
				return nil, nil, nil, errors.New("Init with wrong receiver")
			}
			if tokenParams.Receiver[0].Amount != tokenParams.Amount { // Init with wrong max amount of custom token
				return nil, nil, nil, errors.New("Init with wrong max amount of property")
			}
			if tokenParams.PropertyName == "" {
				return nil, nil, nil, errors.New("Init with wrong name of property")
			}
			if tokenParams.PropertySymbol == "" {
				return nil, nil, nil, errors.New("Init with wrong symbol of property")
			}
		}
	}
	return tokenParams, nil, nil, nil
}

func initToken(instance *txCreationInstance, txToken *tx_ver2.TxToken, txNormal *tx_ver2.Tx, params *tx_generic.TxTokenParams) error {
	txToken.TokenData.Type = params.TokenParams.TokenTxType
	txToken.TokenData.PropertyName = params.TokenParams.PropertyName
	txToken.TokenData.PropertySymbol = params.TokenParams.PropertySymbol
	txToken.TokenData.Mintable = params.TokenParams.Mintable

	switch params.TokenParams.TokenTxType {
	case utils.CustomTokenInit:
		{
			panic(7)
			temp := txNormal
			temp.Proof = new(privacy.ProofV2)
			temp.Proof.Init()

			// set output coins; hash everything but commitment; save the hash to compute the new token ID later
			message := []byte{}
			if len(params.TokenParams.Receiver[0].Message) > 0 {
				if len(params.TokenParams.Receiver[0].Message) > privacy.MaxSizeInfoCoin {
					return utils.NewTransactionErr(utils.ExceedSizeInfoOutCoinError, nil)
				}
				message = params.TokenParams.Receiver[0].Message
			}
			tempPaymentInfo := &privacy.PaymentInfo{PaymentAddress: params.TokenParams.Receiver[0].PaymentAddress, Amount: params.TokenParams.Amount, Message: message}
			createdTokenCoin, errCoin := privacy.NewCoinFromPaymentInfo(tempPaymentInfo)
			if errCoin != nil {
				utils.Logger.Log.Errorf("Cannot create new coin based on payment info err %v", errCoin)
				return errCoin
			}
			if err := temp.Proof.SetOutputCoins([]privacy.Coin{createdTokenCoin}); err != nil {
				utils.Logger.Log.Errorf("Init customPrivacyToken cannot set outputCoins")
				return err
			}
			// the coin was copied onto the proof
			theCoinOnProof, ok := temp.Proof.GetOutputCoins()[0].(*privacy.CoinV2)
			if !ok {
				return utils.NewTransactionErr(utils.UnexpectedError, errors.New("coin should have been ver2"))
			}
			theCoinOnProof.SetCommitment(new(privacy.Point).Identity())
			hashInitToken, err := txToken.TokenData.Hash()
			if err != nil {
				utils.Logger.Log.Error(errors.New("can't hash this token data"))
				return utils.NewTransactionErr(utils.UnexpectedError, err)
			}

			temp.Sig = []byte{}
			temp.SigPubKey = []byte{}

			var plainTokenID *common.Hash
			if params.TokenParams.Mintable {
				propertyID, err := common.Hash{}.NewHashFromStr(params.TokenParams.PropertyID)
				if err != nil {
					return utils.NewTransactionErr(utils.TokenIDInvalidError, err, propertyID.String())
				}
				plainTokenID = propertyID
			} else {
				//NOTICE: @merman update PropertyID calculated from hash of tokendata and shardID
				newHashInitToken := common.HashH(append(hashInitToken.GetBytes(), params.ShardID))
				existed := statedb.PrivacyTokenIDExisted(params.TransactionStateDB, newHashInitToken)
				if existed {
					utils.Logger.Log.Error("INIT Tx Custom Token Privacy is Existed", newHashInitToken)
					return utils.NewTransactionErr(utils.TokenIDExistedError, errors.New("this token is existed in network"))
				}
				plainTokenID = &newHashInitToken
				utils.Logger.Log.Debugf("A new token privacy wil be issued with ID: %+v", newHashInitToken.String())
			}

			// set the unblinded asset tag
			err = theCoinOnProof.SetPlainTokenID(plainTokenID)
			if err != nil {
				return utils.NewTransactionErr(utils.UnexpectedError, err)
			}
			txToken.TokenData.PropertyID = *plainTokenID
			txToken.SetTxNormal(temp)
			return nil
		}
	case utils.CustomTokenTransfer:
		{
			propertyID, _ := common.TokenStringToHash(params.TokenParams.PropertyID)
			dbFacingTokenID := common.ConfidentialAssetID
			utils.Logger.Log.Debugf("Token %+v wil be transfered with", propertyID)

			// fee in pToken is not supported
			feeToken := uint64(0)
			txParams := tx_generic.NewTxPrivacyInitParams(
				params.SenderKey,
				params.TokenParams.Receiver,
				params.TokenParams.TokenInput,
				feeToken,
				params.HasPrivacyToken,
				params.TransactionStateDB,
				propertyID,
				nil,
				nil,
			)
			// proveTxToken
			isBurning, err := proveTxToken(instance, txNormal, txParams)
			if err != nil {
				return utils.NewTransactionErr(utils.PrivacyTokenInitTokenDataError, err)
			}
			if isBurning {
				// show plain tokenID if this is a burning TX
				txToken.TokenData.PropertyID = *propertyID
			} else {
				// tokenID is already hidden in asset tags in coin, here we use the umbrella ID
				txToken.TokenData.PropertyID = dbFacingTokenID
			}
			txToken.SetTxNormal(txNormal)
			return nil
		}
	default:
		return utils.NewTransactionErr(utils.PrivacyTokenTxTypeNotHandleError, errors.New("can't handle this TokenTxType"))
	}
}

func makeTxToken(txPRV *tx_ver2.Tx, pubkey, sig []byte, proof privacy.Proof) *tx_ver2.Tx {
	result := &tx_ver2.Tx{
		TxBase: tx_generic.TxBase{
			Version:              txPRV.Version,
			Type:                 txPRV.Type,
			LockTime:             txPRV.LockTime,
			Fee:                  0,
			PubKeyLastByteSender: common.GetShardIDFromLastByte(txPRV.PubKeyLastByteSender),
			Metadata:             nil,
		},
	}
	var clonedInfo []byte = nil
	var err error
	if txPRV.Info != nil {
		clonedInfo = make([]byte, len(txPRV.Info))
		copy(clonedInfo, txPRV.Info)
	}
	var clonedProof privacy.Proof = nil
	// feed the type to parse proof
	proofType := txPRV.Type
	if proofType == common.TxTokenConversionType {
		proofType = common.TxConversionType
	}
	if proof != nil {
		clonedProof, err = utils.ParseProof(proof, txPRV.Version, proofType)
		if err != nil {
			jsb, _ := json.Marshal(proof)
			utils.Logger.Log.Errorf("Cannot parse proof %s using version %v - type %v", string(jsb), txPRV.Version, txPRV.Type)
			return nil
		}
	}
	var clonedSig []byte = nil
	if sig != nil {
		clonedSig = make([]byte, len(sig))
		copy(clonedSig, sig)
	}
	var clonedPk []byte = nil
	if pubkey != nil {
		clonedPk = make([]byte, len(pubkey))
		copy(clonedPk, pubkey)
	}
	result.Info = clonedInfo
	result.Proof = clonedProof
	result.Sig = clonedSig
	result.SigPubKey = clonedPk
	result.Info = clonedInfo

	return result
}

func createUniqueOTACoinCA(paymentInfo *privacy.PaymentInfo, tokenID *common.Hash) (*privacy.CoinV2, *privacy.Point, error) {
	if tokenID == nil {
		tokenID = &common.PRVCoinID
	}
	for i := privacy.MAX_TRIES_OTA; i > 0; i-- {
		c, sharedSecret, err := privacy.NewCoinCA(paymentInfo, tokenID)
		if tokenID != nil && sharedSecret != nil && c != nil && c.GetAssetTag() != nil {
			utils.Logger.Log.Infof("Created a new coin with tokenID %s, shared secret %s, asset tag %s\n", tokenID.String(), sharedSecret.MarshalText(), c.GetAssetTag().MarshalText())
		}
		if err != nil {
			utils.Logger.Log.Errorf("Cannot parse coin based on payment info err: %v", err)
			return nil, nil, err
		}
		// If previously created coin is burning address
		if sharedSecret == nil {
			// assetTag := privacy.HashToPoint(tokenID[:])
			// c.SetAssetTag(assetTag)
			return c, nil, nil // No need to check db
		}
		// Onetimeaddress should be unique
		// publicKeyBytes := c.GetPublicKey().ToBytesS()
		// here tokenID should always be TokenConfidentialAssetID (for db storage)
		// found, err := statedb.HasOnetimeAddress(stateDB, common.ConfidentialAssetID, publicKeyBytes)
		// if err != nil {
		// 	utils.Logger.Log.Errorf("Cannot check public key existence in DB, err %v", err)
		// 	return nil, nil, err
		// }
		// if !found {
		return c, sharedSecret, nil
		// }
	}
	// MAX_TRIES_OTA could be exceeded if the OS's RNG or the statedb is corrupted
	fmt.Errorf("Cannot create unique OTA after %d attempts", privacy.MAX_TRIES_OTA)
	return nil, nil, errors.New("Cannot create unique OTA")
}

func (inst *txCreationInstance) SendCmdRequestToLedger(requestCmd *LedgerRequest) ([]byte, error) {
	requestBytes, _ := json.Marshal(*requestCmd)
	if err := inst.sendMsgToClient(requestBytes); err != nil {
		return nil, err
	}
	if inst.respondWaitor != nil {
		panic(9)
	}
	respondCh := make(chan []byte)
	inst.respondWaitor = &respondCh
	defer func() {
		inst.respondWaitor = nil
	}()
	respondBytes := <-respondCh
	return respondBytes, nil
}
