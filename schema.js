var typed_schema={
	"description":"Typed json schema",
	"type":"object",
	"properties":{
		"Type":{
			"description":"How the instance is intended to be used",
			"type":"string",
			"enum":["certificate", "encrypted", "encryption", "inner", "integrity", "privatekey", "publickey", "recipient", "signature", "signed"]
		}}};

var versioned_schema={
	"description":"A base class for crypto schemas",
	"type":"object",
	"extends":typed_schema,
	"properties":{
		"Version":{
			"description":"The version of the schema this instance conforms to",
			"type":"string",
			"enum":["1.0"]
		}}};

var publickey_schema = {
	"description":"An RSA public key",
	"type":"object",
	"extends":typed_schema,
	"properties":{
		"Algorithm":{
			"type":"string",
			"enum":["RSA-PKCS1-1.5", "RSA-PKCS1-OAEP"]
		},
		"RsaExponent":{
			"description":"",
			"type":"string"},
		"RsaModulus":{
			"description":"",
			"type":"string"
		}}};

var privatekey_schema = {
	"description":"An RSA private key",
	"type":"object",
	"extends":versioned_schema,
	"properties":{
		"PublicKey":{
			"type":"object",
			"extends":PublicKey
		},
		"Algorithm":{
			"description":"",
			"type":"string",
			"enum":["RSA-PKCS1-1.5", "RSA-PKCS1-OAEP"]
		},
		"PrivateExponent":{
			"description":"",
			"type":"string"
		}}};

var signed_schema = {
	"description":"A signed message",
	"type":"object",
	"extends":versioned_schema,
	"properties":{
		"Signature":{
			"description":"The signature over the SignedData",
			"type":"object",
			"properties":{
				"Value":{
					"description":"",
					"type":"string"},
				"DigestAlgorithm":{
					"description":"",
					"type":"string",
					"enum":["SHA1", "SHA256"] },
				"SignatureAlgorithm":{
					"description":"",
					"type":"string",
					"enum":["RSA-PKCS1-1.5"] },
				"Signer":{
					"description":"",
					"type":"string",
					"format":"email" },
				"PkixChain":{
					"description":"",
					"type":"array",
					"minItems":1,
					"items":{
						"type":"string" } }
			}}}};

var union_schema = {
	"type":[publickey_schema, privatekey_schema, signed_schema]
};

var cert_schema = {
	"description":"A certificate",
	"type":"object",
	"properties":{
		"Version":{
			"description":"",
			"type":"string",
			"enum":["1.0"]},
		"Serial":{
			"description":"",
			"type":"integer",
			"minimum":0
		},
		"Issuer":{
			"description":"",
			"type":"string"},
		"NotBefore":{
			"description":"",
			"type":"string",
			"format":"date-time"
		},
		"NotAfter":{
			"description":"",
			"type":"string",
			"format":"date-time"
		},
		"Name":{
			"description":"",
			"type":"string"},
		"PublicKey":{
			"description":"",
			"type":"object",
			"properties":{
				"Algorithm":{
					"type":"string",
					"enum":["RSA"]
				},
				"RsaExponent":{
					"description":"",
					"type":"string",
					"optional":true},
				"RsaModulus":{
					"description":"",
					"type":"string",
					"optional":true}
			}
		},
		"Extensions":{
			"description":"",
			"type":"array",
			"optional":true,
			"items":{
				"description":"",
				"type":"object",
				"properties":{
					"Name":{
						"description":"",
						"type":"string"},
					"Value":{
						"description":"",
						"type":"any"}
				}}},
		"CriticalExtensions":{
			"type":"array",
			"optional":true,
			"items":{
				"type":"object",
				"properties":{
					"Name":{"type":"string"},
					"Value":{"type":"any"}
				}}}
	}};