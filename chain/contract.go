package chain

import (
	"log"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"mpc/tool"
	"mpc/conf"
	"mpc/tx"
)

func CallWithBlock(url, jsonAbi, contractAddress, defaultBlock, functionName string, args ...interface{}) (interface{}, error) {
	abiObj, err := abi.JSON(strings.NewReader(jsonAbi))
	if err != nil {
		return "", err
	}
	dataByte, err := abiObj.Pack(functionName, args...)
	if err != nil {
		return "", err
	}
	//log.Printf("dataByte: %s", common.Bytes2Hex(dataByte))
	txObj := tx.NewTxObj2("", contractAddress, "", "0x"+common.Bytes2Hex(dataByte))

	txObj.GasLimit = ""
	txObj.GasPrice = ""
	//log.Printf("TxObj: %s", txObj)
	reply, err := Call(url, txObj, defaultBlock)
	return reply, err
}

func SignCall(url, privateKey, jsonAbi, contractAddress, functionName string, args ...interface{}) (string, error) {

	address := tool.PrivateKeyToAddress(privateKey)
	nonce, err := GetTransactionCount(url, address)
	if err != nil {
		return "", err
	}
	return SignCallWithNonce(privateKey, nonce, conf.Default_GasLimit, conf.Default_GasPrice, jsonAbi, contractAddress, functionName, args...)
}

func SignCallWithNonce(privateKey, nonce, gasLimit, gasPrice, jsonAbi, contractAddress, functionName string, args ...interface{}) (string, error) {

	abiObj, err := abi.JSON(strings.NewReader(jsonAbi))
	if err != nil {
		return "", err
	}
	dataByte, err := abiObj.Pack(functionName, args...)
	if err != nil {
		return "", err
	}
	txObj := tx.NewTxObj2(nonce, contractAddress, "", common.Bytes2Hex(dataByte))
	txObj.GasLimit = gasLimit
	txObj.GasPrice = gasPrice
	log.Printf("TxObj: %s", txObj.ToJson())
	return txObj.SignedData(privateKey)
}

func TxData(jsonAbi, functionName string, args ...interface{})(string,error){
	abiObj, err := abi.JSON(strings.NewReader(jsonAbi))
	if err != nil {
		return "", err
	}
	dataByte, err := abiObj.Pack(functionName, args...)
	if err != nil {
		return "", err
	}
	return common.Bytes2Hex(dataByte),nil
}