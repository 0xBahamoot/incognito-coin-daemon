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
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/dataaccessobject/statedb"
	"github.com/incognitochain/incognito-chain/incognitokey"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/privacy/privacy_v2/mlsag"
	"github.com/incognitochain/incognito-chain/rpcserver/bean"
	"github.com/incognitochain/incognito-chain/transaction/tx_generic"
	"github.com/incognitochain/incognito-chain/transaction/tx_ver2"
	"github.com/incognitochain/incognito-chain/transaction/utils"
)

var pendingTx []string
var pendingTxCoins map[string][]string

type txCreationInstance struct {
	TxCID         int
	Type          int
	AccountState  *AccountState
	ViaLedger     bool
	wsConn        *websocket.Conn
	respondWaitor *chan []byte //only 1 respond waitor
	quitCh        chan struct{}
}

var onGoingTxs map[int]*txCreationInstance
var onGoingTxsLck sync.Mutex

func CreateTx(req *API_create_tx_req, wsConn *websocket.Conn) {
	if req.TxType < 0 || req.TxType > 3 {
		w, err := wsConn.NextWriter(websocket.TextMessage)
		if err != nil {
			log.Println(err)
			return
		}
		w.Write([]byte("unsupported TxType"))
		if err := w.Close(); err != nil {
			log.Println(err)
			return
		}
	}
	onGoingTxsLck.Lock()
	accountListLck.RLock()
	txCID := len(onGoingTxs)
	newInstance := txCreationInstance{
		TxCID:        txCID,
		Type:         req.TxType,
		ViaLedger:    req.ViaLedger,
		AccountState: accountList[req.Account],
		wsConn:       wsConn,
		quitCh:       make(chan struct{}),
	}
	onGoingTxs[txCID] = &newInstance
	accountListLck.RUnlock()
	onGoingTxsLck.Unlock()

	go newInstance.Start()

	for {
		select {
		case <-newInstance.quitCh:
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
	switch inst.Type {
	case TXTRANFERPRV:

	case TXTRANFERTOKEN:
	case TXSTAKING:
	case TXSTOPSTAKING:
	}
}

func (inst *txCreationInstance) sendReqToClient(req []byte) error {
	writeWait := 5 * time.Second
	inst.wsConn.SetWriteDeadline(time.Now().Add(writeWait))

	w, err := inst.wsConn.NextWriter(websocket.TextMessage)
	if err != nil {
		log.Println(err)
		return err
	}
	w.Write(req)

	if err := w.Close(); err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func (inst *txCreationInstance) RequestLedgerSignSchnorr() ([]byte, error) {
	request := LedgerRequest{
		Cmd: "signschnorr",
	}

	requestBytes, _ := json.Marshal(request)
	if err := inst.sendReqToClient(requestBytes); err != nil {
		return nil, err
	}
	if inst.respondWaitor != nil {
		panic(9)
	}
	respondCh := make(chan []byte)
	inst.respondWaitor = &respondCh
	respondBytes := <-respondCh

	_ = respondBytes

	var result []byte
	return result, nil
}

func (inst *txCreationInstance) RequestLedgerCreateRingSig() ([]byte, error) {
	request := LedgerRequest{
		Cmd: "createringsig",
	}

	requestBytes, _ := json.Marshal(request)
	if err := inst.sendReqToClient(requestBytes); err != nil {
		return nil, err
	}
	if inst.respondWaitor != nil {
		panic(9)
	}
	respondCh := make(chan []byte)
	inst.respondWaitor = &respondCh
	respondBytes := <-respondCh

	_ = respondBytes
	var result []byte
	return result, nil
}

func createTxPRV(instance *txCreationInstance, tokenID string, paymentInfo []*privacy.PaymentInfo, metadataParam metadata.Metadata, debugKeyset *incognitokey.KeySet) (metadata.Transaction, error) {
	//create tx param
	rawTxParam := bean.CreateRawTxParam{
		SenderKeySet:         debugKeyset,
		ShardIDSender:        instance.AccountState.Account.ShardID,
		PaymentInfos:         paymentInfo,
		HasPrivacyCoin:       true,
		Info:                 nil,
		EstimateFeeCoinPerKb: 0,
	}
	var stateDB *statedb.StateDB
	if NODEMODE == MODESIM {
		stateDB = localnode.GetBlockchain().GetBestStateShard(instance.AccountState.Account.ShardID).GetCopiedTransactionStateDB()
	} else {
		stateDB = TransactionStateDB[instance.AccountState.Account.ShardID]
	}
	tx, err := buildRawTransaction(instance, &rawTxParam, metadataParam, stateDB)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func createTxToken(instance *txCreationInstance, tokenID string, paymentInfos []*privacy.PaymentInfo, metadataParam metadata.Metadata, debugKeyset *incognitokey.KeySet) (metadata.Transaction, error) {
	//create tx param
	rawTxParam := bean.CreateRawTxParam{
		SenderKeySet:         debugKeyset,
		ShardIDSender:        instance.AccountState.Account.ShardID,
		PaymentInfos:         paymentInfos,
		HasPrivacyCoin:       true,
		Info:                 nil,
		EstimateFeeCoinPerKb: 0,
	}
	tx, err := buildRawTransaction(instance, &rawTxParam, metadataParam, TransactionStateDB[instance.AccountState.Account.ShardID])
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func buildRawTransaction(instance *txCreationInstance, params *bean.CreateRawTxParam, meta metadata.Metadata, stateDB *statedb.StateDB) (metadata.Transaction, error) {
	// get output coins to spend and real fee
	inputCoins, realFee, err := chooseCoinsForAccount(instance.AccountState,
		params.PaymentInfos, meta, nil)
	if err != nil {
		return nil, err
	}

	// rewrite TxBase InitializeTxAndParams
	initializingParams := tx_generic.NewTxPrivacyInitParams(&params.SenderKeySet.PrivateKey,
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
			if tx.Sig, tx.SigPubKey, err = signSchnorrHost(initializingParams.SenderSK, tx.Hash()[:]); err != nil {
				return nil, err
			}
		} else {
			if tx.Sig, tx.SigPubKey, err = signSchnorrLedger(instance, tx.Hash()[:]); err != nil {
				return nil, err
			}
		}
		return &tx, nil
	}

	// proveTxToken
	// coins conceal here too
	if err := proveTxPRV(instance, &tx, initializingParams); err != nil {
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
func proveTxPRV(instance *txCreationInstance, tx *tx_ver2.Tx, params *tx_generic.TxPrivacyInitParams) error {
	outputCoins, err := NewCoinV2ArrayFromPaymentInfoArray(params.PaymentInfo, params.TokenID)
	if err != nil {
		fmt.Printf("Cannot parse outputCoinV2 to outputCoins, error %v \n", err)
		return err
	}

	inputCoins := params.InputCoins

	// gen tx proof
	tx.Proof, err = privacy.ProveV2(inputCoins, outputCoins, nil, false, params.PaymentInfo)
	if err != nil {
		return err
	}

	if tx.ShouldSignMetaData() {
		if err := signMetadata(instance, tx, params.SenderSK); err != nil {
			panic(err)
		}
	}

	// ringSig + mlsag
	err = signOnMessage(instance, tx, inputCoins, outputCoins, params, tx.Hash()[:])
	return err
}

//TODO
func proveTxToken(tx *tx_ver2.Tx, params *tx_generic.TxPrivacyInitParams) error {
	return nil
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
		if signature, _, err = signSchnorrHost(debugPrivKey, data); err != nil {
			return err
		}
	} else {
		if signature, _, err = signSchnorrLedger(instance, tx.Hash()[:]); err != nil {
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

	if params.SenderSK != nil {
		privKeysMlsag, err := createPrivKeyMlsagHost(inp, out, params.SenderSK, commitmentToZero)
		if err != nil {
			utils.Logger.Log.Errorf("Cannot create private key of mlsag: %v", err)
			return err
		}
		sag := mlsag.NewMlsag(privKeysMlsag, ring, pi)
		sk, err := privacy.ArrayScalarToBytes(&privKeysMlsag)
		if err != nil {
			utils.Logger.Log.Errorf("tx.SigPrivKey cannot parse arrayScalar to Bytes, error %v ", err)
			return err
		}
		tx.SetPrivateKey(sk)

		// Set Signature
		mlsagSignature, err := sag.Sign(hashedMessage)
		if err != nil {
			return err
		}
		// inputCoins already hold keyImage so set to nil to reduce size
		mlsagSignature.SetKeyImages(nil)
		tx.Sig, err = mlsagSignature.ToBytes()

		return err
	} else {
		tx.Sig, err = createPrivKeyMlsagLedger(instance, inp, out, commitmentToZero)
		if err != nil {
			utils.Logger.Log.Errorf("Cannot create private key of mlsag: %v", err)
			return err
		}
	}
	return nil
}
