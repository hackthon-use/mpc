package conf

const Default_GasPrice string = "0xee6b2801"//"0x9502f9000" //"0x4a817c800"
const Default_GasLimit string = "0x30d40"     //"0x2dc6c0"

const TokenContractAddress = "0x01c5420b9b4fdd8ac10de6d2082e63e81a0af86f"
const TokenContractABI2 = `[{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_amount","type":"uint256"}],"name":"approve","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"supply","type":"uint256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_amount","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_amount","type":"uint256"}],"name":"forceTransfer","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_account","type":"address"}],"name":"unfreeze","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_newAddress","type":"uint256"}],"name":"changeLogicProxy","outputs":[],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"_account","type":"address"}],"name":"accountStatus","outputs":[{"name":"_status","type":"uint8"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"getInitor","outputs":[{"name":"_proxy","type":"address"}],"payable":false,"type":"function"},{"constant":false,"inputs":[],"name":"unfreezeToken","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[],"name":"freezeToken","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_account","type":"address"}],"name":"freeze","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_amount","type":"uint256"}],"name":"transferOrigin","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"getProxy","outputs":[{"name":"_proxy","type":"address"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_amounts","type":"uint256"}],"name":"destroy","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_amount","type":"uint256"}],"name":"transfer","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_issuer","type":"address"},{"name":"_symbol","type":"bytes32"},{"name":"_id","type":"uint256"},{"name":"_maxSupply","type":"uint256"},{"name":"_precision","type":"uint256"},{"name":"_currentSupply","type":"uint256"},{"name":"_closingTime","type":"uint256"},{"name":"_description","type":"string"},{"name":"_hash","type":"uint256"},{"name":"_coreContract","type":"address"}],"name":"init","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"summary","outputs":[{"name":"_id","type":"uint256"},{"name":"_issuer","type":"address"},{"name":"_symbol","type":"bytes32"},{"name":"_maxSupply","type":"uint256"},{"name":"_precision","type":"uint256"},{"name":"_currentSupply","type":"uint256"},{"name":"_description","type":"string"},{"name":"_registerTime","type":"uint256"},{"name":"_closingTime","type":"uint256"},{"name":"_coreContract","type":"address"},{"name":"_hash","type":"uint256"},{"name":"_status","type":"uint8"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"_amounts","type":"uint256"}],"name":"issueMore","outputs":[{"name":"success","type":"bool"}],"payable":false,"type":"function"},{"constant":true,"inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],"name":"allowance","outputs":[{"name":"_allowance","type":"uint256"}],"payable":false,"type":"function"},{"inputs":[],"payable":false,"type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_issuer","type":"address"},{"indexed":false,"name":"_symbol","type":"bytes32"},{"indexed":false,"name":"_id","type":"uint256"},{"indexed":false,"name":"_maxSupply","type":"uint256"},{"indexed":false,"name":"_precision","type":"uint256"},{"indexed":false,"name":"_currentSupply","type":"uint256"},{"indexed":false,"name":"_closingTime","type":"uint256"},{"indexed":false,"name":"_description","type":"string"},{"indexed":false,"name":"_hash","type":"uint256"},{"indexed":false,"name":"_coreContract","type":"address"}],"name":"TokenCreate","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_id","type":"uint256"},{"indexed":false,"name":"_from","type":"address"},{"indexed":false,"name":"_to","type":"address"},{"indexed":false,"name":"_amount","type":"uint256"}],"name":"ForceTransfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_issuer","type":"address"},{"indexed":false,"name":"_id","type":"uint256"},{"indexed":false,"name":"_amounts","type":"uint256"}],"name":"IssueMore","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_issuer","type":"address"},{"indexed":false,"name":"_id","type":"uint256"},{"indexed":false,"name":"_amounts","type":"uint256"}],"name":"Destroy","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"from","type":"address"},{"indexed":false,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"owner","type":"address"},{"indexed":false,"name":"spender","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_res","type":"uint256[]"}],"name":"Init","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_old","type":"uint256"},{"indexed":false,"name":"_new","type":"uint256"}],"name":"ResetCore","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_old","type":"uint256"},{"indexed":false,"name":"_new","type":"uint256"}],"name":"ResetOwner","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_no","type":"uint256"}],"name":"Alert","type":"event"}]`
const TokenContractABI3 = `[{"constant":false,"inputs":[{"name":"_ruleId","type":"bytes32"},{"name":"_property","type":"string"},{"name":"_op","type":"string"},{"name":"_value","type":"string"}],"name":"registerRule","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"id","type":"bytes32"},{"name":"user","type":"address"},{"name":"validator","type":"address"},{"name":"logic","type":"string"},{"name":"requestId","type":"bytes32[]"},{"name":"expired","type":"uint256[]"},{"name":"hash","type":"bytes32[]"},{"name":"properties","type":"string"},{"name":"ops","type":"string"},{"name":"values","type":"string"}],"name":"submitValidation","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"id","type":"bytes32"}],"name":"getRequirement","outputs":[{"name":"client","type":"address"},{"name":"clientName","type":"string"},{"name":"ruleIds","type":"bytes32[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getRequirementIds","outputs":[{"name":"","type":"bytes32[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_id","type":"bytes32"}],"name":"getValidationPart2","outputs":[{"name":"","type":"string"},{"name":"","type":"string"},{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getRuleIds","outputs":[{"name":"","type":"bytes32[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_id","type":"address"}],"name":"getOracleName","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_id","type":"bytes32"}],"name":"getResponse","outputs":[{"name":"responseId","type":"bytes32"},{"name":"requestId","type":"bytes32"},{"name":"hash","type":"bytes32"},{"name":"property","type":"string"},{"name":"encrypedValue","type":"string"},{"name":"expired","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getOracleList","outputs":[{"name":"","type":"address[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_address","type":"address"},{"name":"_name","type":"string"}],"name":"registerOracle","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_id","type":"bytes32"}],"name":"getValidationPart1","outputs":[{"name":"","type":"bytes32"},{"name":"","type":"address"},{"name":"","type":"address"},{"name":"","type":"string"},{"name":"","type":"bytes32[]"},{"name":"","type":"uint256[]"},{"name":"","type":"bytes32[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getResponseIds","outputs":[{"name":"","type":"bytes32[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"requestId","type":"bytes32"},{"name":"oracle","type":"address"},{"name":"property","type":"string"},{"name":"pubKey","type":"bytes32"},{"name":"platformId","type":"bytes32"}],"name":"request","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"getRequestIds","outputs":[{"name":"","type":"bytes32[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"oracles","outputs":[{"name":"id","type":"address"},{"name":"name","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"id","type":"bytes32"},{"name":"client","type":"address"},{"name":"clientName","type":"string"},{"name":"ruleIds","type":"bytes32[]"}],"name":"submitRequirements","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"responseId","type":"bytes32"},{"name":"requestId","type":"bytes32"},{"name":"hash","type":"bytes32"},{"name":"property","type":"string"},{"name":"encrypedValue","type":"string"},{"name":"expired","type":"uint256"}],"name":"oracleCommit","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"getValidationIds","outputs":[{"name":"","type":"bytes32[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_id","type":"bytes32"}],"name":"getRule","outputs":[{"name":"id","type":"bytes32"},{"name":"property","type":"string"},{"name":"op","type":"string"},{"name":"value","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_id","type":"bytes32"}],"name":"getRequest","outputs":[{"name":"requestId","type":"bytes32"},{"name":"requester","type":"address"},{"name":"property","type":"string"},{"name":"pubKey","type":"bytes32"},{"name":"platformId","type":"bytes32"},{"name":"expired","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"}]`

const TokenContractABI = `[
	{
		"constant": false,
		"inputs": [
			{
				"name": "responseId",
				"type": "uint32"
			},
			{
				"name": "requestId",
				"type": "uint32"
			},
			{
				"name": "hash",
				"type": "bytes32"
			},
			{
				"name": "property",
				"type": "string"
			},
			{
				"name": "encrypedValue",
				"type": "string"
			},
			{
				"name": "expired",
				"type": "uint256"
			}
		],
		"name": "oracleCommit",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_address",
				"type": "address"
			},
			{
				"name": "_name",
				"type": "string"
			}
		],
		"name": "registerOracle",
		"outputs": [
			{
				"name": "",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_ruleId",
				"type": "uint32"
			},
			{
				"name": "_property",
				"type": "string"
			},
			{
				"name": "_op",
				"type": "string"
			},
			{
				"name": "_value",
				"type": "string"
			}
		],
		"name": "registerRule",
		"outputs": [
			{
				"name": "",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "requestId",
				"type": "uint32"
			},
			{
				"name": "oracle",
				"type": "address"
			},
			{
				"name": "property",
				"type": "string"
			},
			{
				"name": "pubKey",
				"type": "bytes32"
			},
			{
				"name": "platformId",
				"type": "bytes32"
			}
		],
		"name": "request",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "id",
				"type": "uint32"
			},
			{
				"name": "client",
				"type": "address"
			},
			{
				"name": "clientName",
				"type": "string"
			},
			{
				"name": "ruleIds",
				"type": "uint32[]"
			}
		],
		"name": "submitRequirements",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "id",
				"type": "uint32"
			},
			{
				"name": "user",
				"type": "address"
			},
			{
				"name": "validator",
				"type": "address"
			},
			{
				"name": "logic",
				"type": "string"
			},
			{
				"name": "requestId",
				"type": "uint32[]"
			},
			{
				"name": "expired",
				"type": "uint32[]"
			},
			{
				"name": "hash",
				"type": "bytes32[]"
			},
			{
				"name": "properties",
				"type": "string"
			},
			{
				"name": "ops",
				"type": "string"
			},
			{
				"name": "values",
				"type": "string"
			}
		],
		"name": "submitValidation",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "id",
				"type": "uint32"
			},
			{
				"name": "validator",
				"type": "address"
			}
		],
		"name": "submitValidation2",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "getOracleList",
		"outputs": [
			{
				"name": "",
				"type": "address[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "_id",
				"type": "address"
			}
		],
		"name": "getOracleName",
		"outputs": [
			{
				"name": "",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "requester",
				"type": "address"
			},
			{
				"name": "_id",
				"type": "uint32"
			}
		],
		"name": "getRequest",
		"outputs": [
			{
				"name": "",
				"type": "uint32"
			},
			{
				"name": "",
				"type": "address"
			},
			{
				"name": "",
				"type": "string"
			},
			{
				"name": "",
				"type": "bytes32"
			},
			{
				"name": "",
				"type": "bytes32"
			},
			{
				"name": "",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "requester",
				"type": "address"
			}
		],
		"name": "getRequestIds",
		"outputs": [
			{
				"name": "",
				"type": "uint32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "id",
				"type": "uint32"
			}
		],
		"name": "getRequirement",
		"outputs": [
			{
				"name": "",
				"type": "address"
			},
			{
				"name": "",
				"type": "string"
			},
			{
				"name": "",
				"type": "uint32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "getRequirementIds",
		"outputs": [
			{
				"name": "",
				"type": "uint32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "requester",
				"type": "address"
			},
			{
				"name": "_id",
				"type": "uint32"
			}
		],
		"name": "getResponse",
		"outputs": [
			{
				"name": "",
				"type": "uint32"
			},
			{
				"name": "",
				"type": "uint32"
			},
			{
				"name": "",
				"type": "bytes32"
			},
			{
				"name": "",
				"type": "string"
			},
			{
				"name": "",
				"type": "string"
			},
			{
				"name": "",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "requester",
				"type": "address"
			}
		],
		"name": "getResponseIds",
		"outputs": [
			{
				"name": "",
				"type": "uint32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "_id",
				"type": "uint32"
			}
		],
		"name": "getRule",
		"outputs": [
			{
				"name": "id",
				"type": "uint32"
			},
			{
				"name": "property",
				"type": "string"
			},
			{
				"name": "op",
				"type": "string"
			},
			{
				"name": "value",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "getRuleIds",
		"outputs": [
			{
				"name": "",
				"type": "uint32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "r",
				"type": "address"
			}
		],
		"name": "getValidationIds",
		"outputs": [
			{
				"name": "",
				"type": "uint32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "r",
				"type": "address"
			},
			{
				"name": "_id",
				"type": "uint32"
			}
		],
		"name": "getValidationPart1",
		"outputs": [
			{
				"name": "",
				"type": "uint32"
			},
			{
				"name": "",
				"type": "address"
			},
			{
				"name": "",
				"type": "address"
			},
			{
				"name": "",
				"type": "string"
			},
			{
				"name": "",
				"type": "uint32[]"
			},
			{
				"name": "",
				"type": "uint32[]"
			},
			{
				"name": "",
				"type": "bytes32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "r",
				"type": "address"
			},
			{
				"name": "_id",
				"type": "uint32"
			}
		],
		"name": "getValidationPart2",
		"outputs": [
			{
				"name": "",
				"type": "string"
			},
			{
				"name": "",
				"type": "string"
			},
			{
				"name": "",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"name": "oracles",
		"outputs": [
			{
				"name": "id",
				"type": "address"
			},
			{
				"name": "name",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	}
]`

const BlockChain_Host string = "https://kovan.infura.io/i5fsYBGo4uOrGb26UtgX"