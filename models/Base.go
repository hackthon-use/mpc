package models


type Identity struct {
	User string 	`json:"user"`
	Platform string		`json:"platform"`
	PlatformId string	`json:"platformId"`
}

type EncryptData struct {
	PropertyName string      `json:"propertyName"`    //名称，比如存款，国籍，风险评级，年收入
	Value interface{}        `json:"value"`
	TimeStamp string		`json:"timestamp"`
}

type OnChainData struct {
	PropertyName string     `json:"propertyName"`
	HashValue string        `json:"hashValue"`
	ExpireTimestamp int64   `json:"expireTimestamp"`
	Txid string             `json:"txid"`
}

type Rule struct {
	PropertyName string    `json:"propertyName"`
	Op string			   `json:"op"`
	Value interface{}	   `json:"value"`
}

type MPCRequest struct {
	Identity  Identity   `json:"identity"`
	RuleRelation string  `json:"ruleRel"`
	Rules []Rule         `json:"rules"`
	EncryptData []EncryptData      `json:"encryptData"`
	OnChainData []OnChainData  `json:"onChainData"`
}


type KycResponse struct {
	Status bool
	Message interface{}
}



type VerifyResult struct {
	PropertyName string    `json:"propertyName"`
	Message string    `json:"message"`
}