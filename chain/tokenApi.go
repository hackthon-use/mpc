package chain

import (
	"log"
	"github.com/ethereum/go-ethereum/common"
	"mpc/conf"
	"mpc/tool"
	"mpc/models"
	"math/rand"
	"time"
	"strconv"
)

func TotalSupply(url, tokenAddress string) (supply string, err error) {

	reply, err := CallWithBlock(url, conf.TokenContractABI, tokenAddress, "latest", "totalSupply")
	//log.Printf("SignData: %s, %s", signedData, err)
	if err != nil {
		return "", err
	}
	return reply.(string), nil
}

func BalanceOf(url, tokenAddress, accountAddress string) (balance string, err error) {

	reply, err := CallWithBlock(url, conf.TokenContractABI, tokenAddress, "latest", "balanceOf", common.HexToAddress(accountAddress))
	//log.Printf("SignData: %s, %s", signedData, err)
	if err != nil {
		return "", err
	}
	return reply.(string), nil
}

func SubmitValidation2(url, tokenAddress, nonce, gasLimit, gasPrice, privateKey string, id uint32, validator, user string) (result string, err error)  {
	rand.Seed(time.Now().UnixNano())
	id = rand.Uint32()
	signedData, err := SignCallWithNonce(privateKey, nonce, gasLimit, gasPrice, conf.TokenContractABI, tokenAddress, "submitValidation2",
		id, common.HexToAddress(validator), user)
	log.Printf("signedData: %s, %s", signedData, err)
	if err != nil {
		return "", err
	}
	txHash, err := SendRawTransaction(url, "0x"+signedData)
	//t.Logf("SendRawTransaction: %s, %s", txHash, err)

	return txHash, err
}

func SubmitValidation3(url, tokenAddress, nonce, gasLimit, gasPrice, privateKey string, mpcRequest models.MPCRequest) (result string, err error) {
	rand.Seed(time.Now().UnixNano())
	var id = rand.Uint32()
	user := mpcRequest.Identity.User
	validator := mpcRequest.Identity.Platform
	logic := mpcRequest.RuleRelation
	var requestId, _  = strconv.ParseUint(mpcRequest.OnChainData[0].Txid, 10, 32)
	et := uint64(mpcRequest.OnChainData[0].ExpireTimestamp)
	var expired = strconv.FormatUint(et, 32)
	var hash []byte = []byte(mpcRequest.OnChainData[0].HashValue)
	var properties string = mpcRequest.OnChainData[0].PropertyName
	var ops string = mpcRequest.Rules[0].Op
	var values string = (mpcRequest.EncryptData[0].Value).(string)

	signedData, err := SignCallWithNonce(privateKey, nonce, gasLimit, gasPrice, conf.TokenContractABI, tokenAddress, "submitValidation3",
		id,
		common.HexToAddress(user),
		common.HexToAddress(validator),
		logic,
		requestId,
		expired,
		hash,
		properties,
		ops,
		values)
	log.Printf("signedData: %s, %s", signedData, err)
	if err != nil {
		return "", err
	}
	txHash, err := SendRawTransaction(url, "0x"+signedData)
	//t.Logf("SendRawTransaction: %s, %s", txHash, err)

	return txHash, err
}

func SubmitValidation(url, tokenAddress, nonce, gasLimit, gasPrice, privateKey string, mpcRequest models.MPCRequest) (result string, err error) {
	var id [32]byte
	user := mpcRequest.Identity.User
	validator := mpcRequest.Identity.Platform
	logic := mpcRequest.RuleRelation
	var requestIds uint32
	var expireds uint32
	var hashs [][32]byte
	var properties string
	var ops string
	var values string
	//for index, ocd := range mpcRequest.OnChainData {
		//requestIds = append(requestIds, []byte(ocd.Txid))
		//expireds = append(expireds, uint(ocd.ExpireTimestamp))
		//hashs = append(hashs, []byte(ocd.HashValue))
		//properties += "|" + ocd.PropertyName
		//ops += "|" + mpcRequest.Rules[index].Op
		//values += "|" + mpcRequest.EncryptData[index].Value.(string)
	//}
	//properties = strings.TrimRight(properties, "|")
	//ops = strings.TrimRight(ops, "|")
	//values = strings.TrimRight(values, "|")

	signedData, err := SignCallWithNonce(privateKey, nonce, gasLimit, gasPrice, conf.TokenContractABI, tokenAddress, "submitValidation",
		id,
		common.HexToAddress(user),
		common.HexToAddress(validator),
		logic,
		requestIds,
		expireds,
		hashs,
		properties,
		ops,
		values)
	log.Printf("signedData: %s, %s", signedData, err)
	if err != nil {
		return "", err
	}
	txHash, err := SendRawTransaction(url, "0x"+signedData)
	//t.Logf("SendRawTransaction: %s, %s", txHash, err)

	return txHash, err
}


func BalanceOfWithBlock(url, tokenAddress, accountAddress, defaultBlock string) (balance string, err error) {

	reply, err := CallWithBlock(url, conf.TokenContractABI, tokenAddress, defaultBlock, "balanceOf", common.HexToAddress(accountAddress))
	//log.Printf("SignData: %s, %s", signedData, err)
	if err != nil {
		return "", err
	}
	return reply.(string), nil
}

func Transfer(url, tokenAddress, to, value, nonce, gasLimit, gasPrice, privateKey string) (hash string, err error) {

	signedData, err := SignCallWithNonce(privateKey, nonce, gasLimit, gasPrice, conf.TokenContractABI, tokenAddress, "transfer", common.HexToAddress(to), tool.HexToBigInt(value))
	log.Printf("signedData: %s, %s", signedData, err)
	if err != nil {
		return "", err
	}
	txHash, err := SendRawTransaction(url, "0x"+signedData)
	//t.Logf("SendRawTransaction: %s, %s", txHash, err)

	return txHash, err
}

func TransferFrom(url, tokenAddress, from, to, value, nonce, gasLimit, gasPrice, privateKey string) (hash string, err error) {

	signedData, err := SignCallWithNonce(privateKey, nonce, gasLimit, gasPrice, conf.TokenContractABI, tokenAddress, "transferFrom", common.HexToAddress(from), common.HexToAddress(to), tool.HexToBigInt(value))
	//log.Printf("Transfer: %s, %s", signedData, err)
	if err != nil {
		return "", err
	}
	txHash, err := SendRawTransaction(url, "0x"+signedData)
	//t.Logf("SendRawTransaction: %s, %s", txHash, err)

	return txHash, err
}

func Approve(url, tokenAddress, spender, value, nonce, gasLimit, gasPrice, privateKey string) (hash string, err error) {

	signedData, err := SignCallWithNonce(privateKey, nonce, gasLimit, gasPrice, conf.TokenContractABI, tokenAddress, "approve", common.HexToAddress(spender), tool.HexToBigInt(value))
	//log.Printf("Transfer: %s, %s", signedData, err)
	if err != nil {
		return "", err
	}
	txHash, err := SendRawTransaction(url, "0x"+signedData)
	//t.Logf("SendRawTransaction: %s, %s", txHash, err)

	return txHash, err
}

func Allowance(url, tokenAddress, owner, spender string) (amount string, err error) {

	reply, err := CallWithBlock(url, conf.TokenContractABI, tokenAddress, "latest", "allowance", common.HexToAddress(owner), tool.HexToBigInt(spender))
	//log.Printf("SignData: %s, %s", signedData, err)
	if err != nil {
		return "", err
	}
	return reply.(string), nil
}

func ReadContract(url, abi, contractAddress, method string) (reply interface{}, err error) {

	return CallWithBlock(url, abi, contractAddress, "latest", method)
}
