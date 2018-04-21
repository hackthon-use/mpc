package tool

import (
	"math/big"
	"strconv"
	"strings"
	"github.com/ethereum/go-ethereum/crypto"
)

func IntToHex(num int64) string {
	return "0x" + strconv.FormatInt(num, 16)
}

func HexToInt(hexStr string) (int64, error) {
	if IsEmpty(hexStr) || hexStr == "0x" {
		return 0, nil
	}
	return strconv.ParseInt(Strip0x(hexStr), 16, 64)
}

func HexToBigInt(hexStr string) *big.Int {
	bigInt := new(big.Int)
	if IsEmpty(hexStr) {
		bigInt.SetString("0", 0)
	} else if strings.HasPrefix(hexStr, "0x") {
		bigInt.SetString(hexStr, 0)
	} else {
		bigInt.SetString(hexStr, 16)
	}
	return bigInt
}

func HexToIntWithoutError(hexStr string) int64 {
	reply, err := HexToInt(hexStr)
	if err != nil {
		return 0
	}
	return reply
}

func HexToUintWithoutError(hexStr string) uint64 {
	if IsEmpty(hexStr) || hexStr == "0x" {
		return 0
	}
	reply, err := strconv.ParseUint(Strip0x(hexStr), 16, 64)
	if err != nil {
		return 0
	}
	return reply
}

func IsEmpty(obj interface{}) bool {
	if obj == nil {
		return true
	}
	switch v := obj.(type) {
	case string:
		return v == ""
	}
	return true

}

func Strip0x(input string) string {
	if len(input) >= 2 && strings.HasPrefix(input, "0x") {
		return Substr(input, 2, len(input))
	}
	return input
}


func Substr(str string, start, length int) string {
	rs := []rune(str)
	rl := len(rs)
	end := 0

	if start < 0 {
		start = rl - 1 + start
	}
	end = start + length

	if start > end {
		start, end = end, start
	}

	if start < 0 {
		start = 0
	}
	if start > rl {
		start = rl
	}
	if end < 0 {
		end = 0
	}
	if end > rl {
		end = rl
	}

	return string(rs[start:end])
}

func RightPadString(stringToPad, padChar string, length int) string {
	var repreatedPadChar = ""
	count := length - len(stringToPad)
	for index := 0; index < count; index++ {
		repreatedPadChar += padChar
	}
	return repreatedPadChar + stringToPad
}

func ToEther(hexValue string) string {
	return ToBalance(HexToIntStr(hexValue), 18)
}

func ToBalance(value string, decimals int) string {
	val := RightPadString(value, "0", decimals+1)
	prefixVal := Substr(val, 0, len(val)-decimals)
	return prefixVal + "." + Substr(val, len(val)-decimals, decimals)
}

func HexToIntStr(hexStr string) string {
	return HexToBigInt(hexStr).String()
}

func PrivateKeyToAddress(privateKey string) (address string) {
	key, _ := crypto.HexToECDSA(privateKey)
	return crypto.PubkeyToAddress(key.PublicKey).Hex()
}