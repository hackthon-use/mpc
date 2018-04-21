package controllers

import (
	"crypto/rsa"
	"encoding/pem"
	"crypto/x509"
	"crypto/rand"
	"fmt"
	"crypto/sha256"
	"os"
	"github.com/farmerx/gorsa"
	"crypto"
	"github.com/astaxie/beego"
	"encoding/json"
	"crypto/md5"
	"time"
	"strconv"
	"strings"
	"mpc/chain"
	"mpc/tool"
	"mpc/tx"
	"mpc/conf"
	"mpc/models"
)

func Verify1(msg, pubkey []byte) {
	block, _ := pem.Decode(pubkey)
	if block == nil {
		panic("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("pubInterface is nil")
	}
	pub := pubInterface.(*rsa.PublicKey)
	encrypt, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	if err != nil {
		panic("Encrypt failed")
	}
	beego.Debug(encrypt)
}

func Verify2(msg, pubkey []byte) {
	secretMessage := []byte("send reinforcements, we're going to advance")
	label := []byte("orders")

	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	pki, _ := x509.ParsePKIXPublicKey(pubkey)
	publicKey, isPublicKey := pki.(*rsa.PublicKey)
	fmt.Println(isPublicKey)

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, publicKey, secretMessage, label)
	if err != nil {
		beego.Debug(os.Stderr, "Error from encryption: %s\n", err)
		return
	}

	// Since encryption is a randomized function, ciphertext will be
	// different each time.
	beego.Debug("Ciphertext: %x\n", ciphertext)
}



func Verify(msg []byte, privatekey string, publickey string) {
	if err := gorsa.RSA.SetPublicKey(publickey); err != nil {
		beego.Debug(`set public key :`, err)
	}
	if err := gorsa.RSA.SetPrivateKey(privatekey); err != nil {
		beego.Debug(`set private key :`, err)
	}

	prikey, err := gorsa.RSA.GetPrivatekey()
	if err != nil {
		beego.Debug("encrypt failed ", err)
	}
	hashed := sha256.Sum256(msg)
	signature, err := rsa.SignPKCS1v15(rand.Reader, prikey, crypto.SHA256, hashed[:])
	if err != nil {
		beego.Debug(os.Stderr, "Error from signing: %s\n", err)
		return
	}
	beego.Debug("Signature: %x\n", signature)

	pukey, err := gorsa.RSA.GetPublickey()
	h := sha256.Sum256(msg)
	err = rsa.VerifyPKCS1v15(pukey, crypto.SHA256, h[:], signature)
	if err != nil {
		beego.Debug(os.Stderr, "Error from verification: %s\n", err)
	} else {
		beego.Debug("signature is true")
	}


	msg = []byte(string(msg) + "a")
	h = sha256.Sum256(msg)
	err = rsa.VerifyPKCS1v15(pukey, crypto.SHA256, h[:], signature)
	if err != nil {
		beego.Debug(os.Stderr, "Error from verification: %s\n", err)
	} else {
		beego.Debug("signature is true")
	}
}

type KycController struct {
	beego.Controller
}


// @Title KYC
// @Param MPCRequest body models.MPCRequest true
// @Success 200 string
// @router /compute [post]
func (kc *KycController) Compute() {
	var mpcrequest models.MPCRequest
	json.Unmarshal(kc.Ctx.Input.RequestBody, &mpcrequest)

	//kc.Ctx.ResponseWriter.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")       //允许访问源
	kc.Ctx.ResponseWriter.Header().Set("Access-Control-Allow-Origin", "*")
	kc.Ctx.ResponseWriter.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS")    //允许post访问
	kc.Ctx.ResponseWriter.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization") //header的类型
	kc.Ctx.ResponseWriter.Header().Set("Access-Control-Max-Age", "1728000")
	kc.Ctx.ResponseWriter.Header().Set("Access-Control-Allow-Credentials", "true")
	kc.Ctx.ResponseWriter.Header().Set("content-type", "application/json")

	OnChainData := mpcrequest.OnChainData
	EncryptData := mpcrequest.EncryptData
	Rules := mpcrequest.Rules
	RuleRel := mpcrequest.RuleRelation

	beego.Debug("onchaindata: ", OnChainData)
	beego.Debug("encryptdata: ", EncryptData)
	beego.Debug("rules: ", Rules)
	beego.Debug("ruleRel: ", RuleRel)

	var results []models.VerifyResult

	//验证hash
	for _, v := range EncryptData {
		beego.Debug("k ", v.PropertyName, " v ", v.Value, " time ", v.TimeStamp)
	}
	for _, v := range EncryptData {
		pn := v.PropertyName
		ts := v.TimeStamp
		va := v.Value.(string)
		d := []byte(ts + "," + va)
		has := md5.Sum(d)
		md5str := fmt.Sprintf("%x", has)
		beego.Debug("md5str: ", md5str)
		onchainHash := GetOnChainDataByProp(pn, OnChainData).HashValue
		beego.Debug("onchain: ", onchainHash)
		if onchainHash != md5str {
			kc.Data["json"] = &models.KycResponse{Status: false, Message: "验证hash失败"}
			kc.ServeJSON()
			return
		}
	}

	//判断是否符合规则
	for _, rule := range Rules {
		pn := rule.PropertyName
		op := rule.Op
		ruleValue := rule.Value
		onChainData := GetOnChainDataByProp(pn, OnChainData)
		encryptData := GetEncryptDataByProp(pn, EncryptData)
		ts, _ := strconv.ParseInt(encryptData.TimeStamp, 10, 64)
		va := encryptData.Value
		expire := onChainData.ExpireTimestamp

		if time.Now().Unix() > ts + expire * 3600 {
			kc.Data["json"] = &models.KycResponse{Status: false, Message: "数据已过期, 规则 " + rule.PropertyName + " 验证失败"}
			kc.ServeJSON()
			return
		}
		if pn == "deposit" {
			rv, _ := strconv.ParseInt(ruleValue.(string), 10, 64)
			va, _ := strconv.ParseInt(va.(string), 10, 64)
			if op == ">" || op == ">=" {
				if va < rv {
					kc.Data["json"] = &models.KycResponse{Status: false, Message: "存款不足 " + rule.PropertyName + " 验证失败"}
					kc.ServeJSON()
					return
				}
			} else if op == "<" || op == "<=" {
				if va > rv {
					kc.Data["json"] = &models.KycResponse{Status: false, Message: "存款太多？ " + rule.PropertyName + " 验证失败"}
					kc.ServeJSON()
					return
				}
			}
			result := models.VerifyResult{PropertyName: pn, Message: "验证存款成功"}
			results = append(results, result)
		} else if pn == "nation" {
			rv := ruleValue.(string)
			va := va.(string)
			if op == "in" {
				nations := strings.Split(rv, ",")
				flag := false
				for _, nation := range nations {
					if nation == va {
						flag = true
					}
				}
				if flag == false {
					kc.Data["json"] = &models.KycResponse{Status: false, Message: "国籍信息不符 " + rule.PropertyName + " 验证失败"}
					kc.ServeJSON()
					return
				}
			}
			result := models.VerifyResult{PropertyName: pn, Message: "验证国籍成功"}
			results = append(results, result)
		} else if pn == "yearlyincome" {
			rv, _ := strconv.ParseInt(ruleValue.(string), 10, 64)
			va, _ := strconv.ParseInt(va.(string), 10, 64)
			if op == ">" || op == ">=" {
				if va < rv {
					kc.Data["json"] = &models.KycResponse{Status: false, Message: "年收入不足 " + rule.PropertyName + " 验证失败"}
					kc.ServeJSON()
					return
				}
			}
			result := models.VerifyResult{PropertyName: pn, Message: "验证年收入成功"}
			results = append(results, result)
		} else if pn == "investassessment" {       //1-5分，分数越高，风险承受能力越高
			rv, _ := strconv.ParseInt(ruleValue.(string), 10, 64)
			va, _ := strconv.ParseInt(va.(string), 10, 64)
			if va < rv {
				kc.Data["json"] = &models.KycResponse{Status: false, Message: "风险等级不够 " + rule.PropertyName + " 验证失败"}
				kc.ServeJSON()
				return
			}
			result := models.VerifyResult{PropertyName: pn, Message: "验证风险评级成功"}
			results = append(results, result)
		}
	}


	//规则结果汇总
	//TODO

	Test_Balance(mpcrequest)

	kc.Data["json"] = &models.KycResponse{Status: true, Message: results}
	kc.ServeJSON()
}

func GetEncryptDataByProp(propName string, data []models.EncryptData) models.EncryptData {
	for _, v := range data {
		if v.PropertyName == propName {
			return v
		}
	}
	return models.EncryptData{}
}

func GetOnChainDataByProp(propName string, data []models.OnChainData) models.OnChainData {
	for _, v := range data {
		if v.PropertyName == propName {
			return v
		}
	}
	return models.OnChainData{}
}



//func SendEthTransaction() {
//	var connection = web3.NewWeb3(providers.NewHTTPProvider("https://kovan.infura.io/i5fsYBGo4uOrGb26UtgX", 10, false))
//	transaction := new(dto.TransactionParameters)
//	transaction.From = "0x712bf700778530d52805abc4e7e94c0eb3f61e8e"
//	transaction.To = "0x712bf700778530d52805abc4e7e94c0eb3f61e8e"
//	transaction.Value = big.NewInt(10)
//	transaction.Gas = big.NewInt(40000)
//	transaction.Data = types.ComplexString("p2p transaction")
//	txID, err := connection.Eth.SendTransaction(transaction)
//	if err != nil {
//		beego.Debug("send transaction failed")
//	}
//	beego.Debug("txid: ", txID)
//}

const KYPABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"_ruleId\",\"type\":\"bytes32\"},{\"name\":\"_property\",\"type\":\"string\"},{\"name\":\"_op\",\"type\":\"string\"},{\"name\":\"_value\",\"type\":\"string\"}],\"name\":\"registerRule\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"id\",\"type\":\"bytes32\"},{\"name\":\"user\",\"type\":\"address\"},{\"name\":\"validator\",\"type\":\"address\"},{\"name\":\"logic\",\"type\":\"string\"},{\"name\":\"requestId\",\"type\":\"bytes32[]\"},{\"name\":\"expired\",\"type\":\"uint256[]\"},{\"name\":\"hash\",\"type\":\"bytes32[]\"},{\"name\":\"properties\",\"type\":\"string\"},{\"name\":\"ops\",\"type\":\"string\"},{\"name\":\"values\",\"type\":\"string\"}],\"name\":\"submitValidation\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"id\",\"type\":\"bytes32\"}],\"name\":\"getRequirement\",\"outputs\":[{\"name\":\"client\",\"type\":\"address\"},{\"name\":\"clientName\",\"type\":\"string\"},{\"name\":\"ruleIds\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getRequirementIds\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_id\",\"type\":\"bytes32\"}],\"name\":\"getValidationPart2\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getRuleIds\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_id\",\"type\":\"address\"}],\"name\":\"getOracleName\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_id\",\"type\":\"bytes32\"}],\"name\":\"getResponse\",\"outputs\":[{\"name\":\"responseId\",\"type\":\"bytes32\"},{\"name\":\"requestId\",\"type\":\"bytes32\"},{\"name\":\"hash\",\"type\":\"bytes32\"},{\"name\":\"property\",\"type\":\"string\"},{\"name\":\"encrypedValue\",\"type\":\"string\"},{\"name\":\"expired\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getOracleList\",\"outputs\":[{\"name\":\"\",\"type\":\"address[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_address\",\"type\":\"address\"},{\"name\":\"_name\",\"type\":\"string\"}],\"name\":\"registerOracle\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_id\",\"type\":\"bytes32\"}],\"name\":\"getValidationPart1\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\"},{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"bytes32[]\"},{\"name\":\"\",\"type\":\"uint256[]\"},{\"name\":\"\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getResponseIds\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"requestId\",\"type\":\"bytes32\"},{\"name\":\"oracle\",\"type\":\"address\"},{\"name\":\"property\",\"type\":\"string\"},{\"name\":\"pubKey\",\"type\":\"bytes32\"},{\"name\":\"platformId\",\"type\":\"bytes32\"}],\"name\":\"request\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getRequestIds\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"oracles\",\"outputs\":[{\"name\":\"id\",\"type\":\"address\"},{\"name\":\"name\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"id\",\"type\":\"bytes32\"},{\"name\":\"client\",\"type\":\"address\"},{\"name\":\"clientName\",\"type\":\"string\"},{\"name\":\"ruleIds\",\"type\":\"bytes32[]\"}],\"name\":\"submitRequirements\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"responseId\",\"type\":\"bytes32\"},{\"name\":\"requestId\",\"type\":\"bytes32\"},{\"name\":\"hash\",\"type\":\"bytes32\"},{\"name\":\"property\",\"type\":\"string\"},{\"name\":\"encrypedValue\",\"type\":\"string\"},{\"name\":\"expired\",\"type\":\"uint256\"}],\"name\":\"oracleCommit\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getValidationIds\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_id\",\"type\":\"bytes32\"}],\"name\":\"getRule\",\"outputs\":[{\"name\":\"id\",\"type\":\"bytes32\"},{\"name\":\"property\",\"type\":\"string\"},{\"name\":\"op\",\"type\":\"string\"},{\"name\":\"value\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_id\",\"type\":\"bytes32\"}],\"name\":\"getRequest\",\"outputs\":[{\"name\":\"requestId\",\"type\":\"bytes32\"},{\"name\":\"requester\",\"type\":\"address\"},{\"name\":\"property\",\"type\":\"string\"},{\"name\":\"pubKey\",\"type\":\"bytes32\"},{\"name\":\"platformId\",\"type\":\"bytes32\"},{\"name\":\"expired\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"


var (
	mainAddress = "0x712bf700778530d52805abc4e7e94c0eb3f61e8e"
	mainPrivateKey = "4b258a07cc98aefc6b386c6466fe8443c3cbcddca19e0260302faa014f7ee837"
	defaultGasPrice int64  = 4000000002
	defaultGasLimit int64  = 91000
	nodeURL = "https://kovan.infura.io/i5fsYBGo4uOrGb26UtgX"
)

func Test_SendTx(){
	nonce, err := chain.GetTransactionCount(nodeURL, mainAddress)
	if err != nil {
		return
	}
	to := "0x712bf700778530d52805abc4e7e94c0eb3f61e8e"
	value := tool.IntToHex(10000000000000000) //0.01
	gasLimit := tool.IntToHex(defaultGasLimit)
	gasPrice := tool.IntToHex(defaultGasPrice)
	txObj := tx.NewTxObj(nonce, to, value, gasLimit, gasPrice, "")
	fmt.Println(txObj)
	txData,err := txObj.SignedData(mainPrivateKey)
	if err != nil {
		return
	}
	txHash,err := chain.SendRawTransaction(nodeURL, "0x"+txData)
	fmt.Printf("txHash： %s, %s\n", txHash, err)
}



func Test_Balance(request models.MPCRequest) {
	tokenContract := conf.TokenContractAddress
	privatekey := "4b258a07cc98aefc6b386c6466fe8443c3cbcddca19e0260302faa014f7ee837"
	nonce, err := chain.GetTransactionCount(conf.BlockChain_Host, mainAddress)
	gasLimit := tool.IntToHex(defaultGasLimit)
	gasPrice := tool.IntToHex(defaultGasPrice)
	if err != nil {
		return
	}
	txHash,err := chain.SubmitValidation2(conf.BlockChain_Host, tokenContract, nonce, gasLimit, gasPrice, privatekey, 0, request.Identity.Platform)
	fmt.Printf("txHash： %s, %s\n", txHash, err)
}