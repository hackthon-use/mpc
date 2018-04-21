package chain

import (
	"errors"
	"time"
	"mpc/jsonrpc2"
	"mpc/tx"
)

type Block struct {
	Number           string        `json:"number"`
	Hash             string        `json:"hash"`
	ParentHash       string        `json:"parentHash"`
	Nonce            string        `json:"nonce"`
	Sha3Uncles       string        `json:"sha3Uncles"`
	LogsBloom        string        `json:"logsBloom"`
	TransactionsRoot string        `json:"transactionsRoot"`
	StateRoot        string        `json:"stateRoot"`
	Miner            string        `json:"miner"`
	Difficulty       string        `json:"difficulty"`
	TotalDifficulty  string        `json:"totalDifficulty"`
	ExtraData        string        `json:"extraData"`
	Size             string        `json:"size"`
	GasLimit         string        `json:"gasLimit"`
	GasUsed          string        `json:"gasUsed"`
	Timestamp        string        `json:"timestamp"`
	Transactions     []interface{} `json:"transactions"`
	Uncles           []interface{} `json:"uncles"`
}

type Transaction struct {
	Hash             string `json:"hash"`
	Nonce            string `json:"nonce"`
	BlockHash        string `json:"blockHash"`
	BlockNumber      string `json:"blockNumber"`
	TransactionIndex string `json:"transactionIndex"`
	From             string `json:"from"`
	To               string `json:"to"`
	Value            string `json:"value"`
	GasPrice         string `json:"gasPrice"`
	Gas              string `json:"gas"`
	Input            string `json:"input"`
}

// type TxObj struct {
// 	Nonce    string `json:"nonce,omitempty"`
// 	From     string `json:"from,omitempty"`
// 	To       string `json:"to,omitempty"`
// 	Value    string `json:"value,omitempty"`
// 	GasPrice string `json:"gasPrice,omitempty"`
// 	Gas      string `json:"gas,omitempty"`
// 	Data     string `json:"data,omitempty"`
// }

// func Sign(privateKey string, tx TxObj) {
// 	signedTx, _ := types.NewTransaction(
// 		tool.HexToUintWithoutError(tx.Nonce),
// 		common.HexToAddress(tx.To),
// 		tool.HexToBigInt(tx.Value),
// 		tool.HexToBigInt(tx.GasPrice),
// 		tool.HexToBigInt(tx.Gas),
// 		common.FromHex(tx.Data),
// 	).WithSignature(
// 		types.HomesteadSigner{},
// 		common.Hex2Bytes(privateKey),
// 	)
// 	log.Printf("signedTx: %s", signedTx.String())
// }

func GetLatestBlockNumber(url string) (string, error) {
	var reply string
	err := jsonrpc2.Call(url, "eth_blockNumber", []string{}, &reply)
	return reply, err
}

func GetGasPrice(url string) (result string, err error) {
	var reply string
	er := jsonrpc2.Call(url, "eth_gasPrice", []string{}, &reply)
	return reply, er
}

func GetBlock(url, blockNumber string, hasTx bool) (Block, error) {
	//var reply interface{}
	var reply = Block{}
	var params = [2]interface{}{}
	params[0] = blockNumber
	params[1] = hasTx
	err := jsonrpc2.Call(url, "eth_getBlockByNumber", params, &reply)
	return reply, err
}


func GetBalance(url, address string) (result string, err error) {
	var reply string
	var params = [2]string{}
	params[0] = address
	params[1] = "latest"
	er := jsonrpc2.Call(url, "eth_getBalance", params, &reply)
	return reply, er
}

func GetTransactionCount(url, address string) (result string, err error) {
	var reply string
	var params = [2]string{}
	params[0] = address
	params[1] = "latest"
	er := jsonrpc2.Call(url, "eth_getTransactionCount", params, &reply)
	return reply, er
}

func GetTransactionReceipt(url, txHash string) (result interface{}, err error) {
	var reply interface{}
	var params = [1]string{}
	params[0] = txHash
	er := jsonrpc2.Call(url, "eth_getTransactionReceipt", params, &reply)
	return reply, er
}

func GetTxReceipt(url, txHash string, reply interface{}) (err error) {
	//reply := types.Receipt{}
	var params = [1]string{}
	params[0] = txHash
	er := jsonrpc2.Call(url, "eth_getTransactionReceipt", params, &reply)
	return er
}

func NewFilter(url string, param interface{}) (result interface{}, err error) {
	var reply interface{}
	var params = make([]interface{}, 1)
	params[0] = param
	er := jsonrpc2.Call(url, "eth_getFilterChanges", params, &reply)
	return reply, er
}

func SendRawTransaction(url, txData string) (result string, err error) {
	var reply string
	var params = [1]string{}
	params[0] = txData
	er := jsonrpc2.Call(url, "eth_sendRawTransaction", params, &reply)
	return reply, er
}

func Call(url string, param *tx.TxObj, defaultBlock string) (result interface{}, err error) {
	var reply interface{}
	var params = make([]interface{}, 2)
	params[0] = param
	params[1] = defaultBlock
	er := jsonrpc2.Call(url, "eth_call", params, &reply)
	return reply, er
}

func GetTxReceiptWithTimes(url, txHash string, reply interface{}, times int) (err error) {
	if times > 10 {
		times = 10
	}
	for index := 0; index < times; index++ {
		if index > 0 {
			time.Sleep(time.Second * time.Duration(3))
		}
		//log.Printf("fetch: %d,%s,%s", index, time.Now(), txHash)
		err := GetTxReceipt(url, txHash, &reply)
		if err == nil {
			return nil
		}
		//time.Sleep(time.Second * time.Duration(3*index+3))
		//<-time.Tick(time.Second * time.Duration(3*index+3))
	}
	return errors.New("not find txReceipt")
}

// func GetFirstBlockNumByDate(timeStamp int64) (blockNum int64, err error) {
// 	//log.Printf("Method: GetFirstBlockNumByDate..... %d", timeStamp)
// 	lastestBlock, err := GetLatestBlockNumber(conf.BlockChain_Host)
// 	if err != nil {
// 		return 0, err
// 	}

// 	lastestBlockNum := tool.HexToIntWithoutError(lastestBlock)
// 	lastestBlockTime, err := GetBlockTime(lastestBlockNum)
// 	if err != nil {
// 		return 0, err
// 	}
// 	//log.Printf("Method: GetFirstBlockNumByDate..... %d,%d,%s", timeStamp, lastestBlockNum, time.Unix(lastestBlockTime, 0).Format("2006-01-02 15:04:05"))
// 	if timeStamp > lastestBlockTime {
// 		return 0, errors.New("future timestamp")
// 	}
// 	return GetNextBlockNum(timeStamp, 0, lastestBlockNum, 1000)
// }

// func GetNextBlockNum(timeStamp, startBlockNum, endBlockNum, count int64) (int64, error) {
// 	//log.Printf("Method: GetNextBlockNum.....%d,%d,%d,%d", timeStamp, count, startBlockNum, endBlockNum)

// 	count = count - 1
// 	if count < 1 {
// 		return 0, errors.New("over flow the max iterations")
// 	}
// 	if endBlockNum < startBlockNum {
// 		return 0, errors.New("endBlock must greater than startBlock")
// 	}
// 	nextBlock := (endBlockNum+startBlockNum)/2 + (endBlockNum-startBlockNum)%2

// 	nextBlockTime, err := GetBlockTime(nextBlock)
// 	if err != nil {
// 		return 0, err
// 	}
// 	//log.Printf("nextBlock: %d,%s", nextBlock, time.Unix(nextBlockTime, 0).Format("2006-01-02 15:04:05"))
// 	if nextBlockTime < timeStamp {
// 		return GetNextBlockNum(timeStamp, nextBlock, endBlockNum, count)
// 	} else if nextBlockTime == timeStamp || nextBlock-startBlockNum <= 1 {
// 		return nextBlock, nil
// 	} else {
// 		return GetNextBlockNum(timeStamp, startBlockNum, nextBlock, count)
// 	}
// }

// func GetBlockTime(blockNum int64) (int64, error) {
// 	//log.Printf("GetBlockTime: %d,%s", blockNum, strconv.FormatInt(blockNum, 10))
// 	block, err := GetBlock(conf.BlockChain_Host, strconv.FormatInt(blockNum, 10), false)
// 	if err != nil {
// 		return 0, err
// 	}
// 	return tool.AToInt64WithoutErr(block.Timestamp), nil
// }

// func GetTopics(nodeURL, txhash string) []string{
	
// 	reply := tx.TxReceipt{}
// 	err := GetTxReceipt(nodeURL, txhash, &reply)
// 	//rp,err := chain.GetTransactionReceipt(nodeURL, txhash)
// 	//fmt.Printf("reply: %s, %s\n", reply, err)
// 	if err != nil {
// 		return nil
// 	}
// 	return reply.GetLogTopics()
// }