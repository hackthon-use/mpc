
package chain

import (
	"fmt"
	"testing"
	"mpc/tool"
	"mpc/conf"
	"mpc/tx"
)

var (
	mainAddress = ""
	mainPrivateKey = ""
	defaultGasPrice int64  = 4000000001
	defaultGasLimit int64  = 21000
)

func Test_LastBlock(t *testing.T){
	// "http://106.15.186.16:8545"  "http://47.100.57.16:9000"
	reply,err := GetLatestBlockNumber(conf.BlockChain_Host)
	fmt.Printf("LastBlock: %s, %s", tool.HexToIntWithoutError(reply), err)
}

func Test_SendSignedTx(t *testing.T){
	// "http://106.15.186.16:8545"  "http://47.100.57.16:9000"
	signedTxData := "0x0000"
	hash,err := SendRawTransaction(conf.BlockChain_Host,signedTxData)
	fmt.Println(hash, err)
}

func Test_SendTx(t *testing.T){
	nonce, err := GetTransactionCount(conf.BlockChain_Host, mainAddress)
	if err != nil {
		return
	}
	to := ""
	value := tool.IntToHex(10000000000000000) //0.01
	gasLimit := tool.IntToHex(defaultGasLimit)
	gasPrice := tool.IntToHex(defaultGasPrice)
	txObj := tx.NewTxObj(nonce, to, value, gasLimit, gasPrice, "")
	fmt.Println(txObj)
	txData,err := txObj.SignedData(mainPrivateKey)
	if err != nil {
		return 
	}
	txHash,err := SendRawTransaction(conf.BlockChain_Host, "0x"+txData)
	fmt.Printf("txHash： %s, %s\n", txHash, err)
}

func Test_Balance(t *testing.T) {
	tokenContract := "0x4cd988afbad37289baaf53c13e98e2bd46aaea8c"
	accountAddr := "0x105cE240AbED39501054A35496e4B81D9Af4f2b0"
	balance, _ := BalanceOf(conf.BlockChain_Host, tokenContract, accountAddr)
	fmt.Printf("balance: %s \n", tool.ToEther(balance))
	t.Errorf("balance: %s", tool.ToEther(balance))
}