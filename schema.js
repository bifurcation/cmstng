var union = {
	"additionalProperties":"false",
	"type":
	[
		{
			"type":"object",
			"properties":{
				"foo":{"type":"string"}
			}
		},
		{
			"type":"object",
			"properties":{
				"bar":{"type":"string"}
			}
		}
]
};

var union_inst = {
	"foo":"boo",
	"bat":"boo"
};

var base_schema = {
	"description":"A base class for crypto schemas",
	"type":"object",
	"properties":{
		"Version":{
			"description":"The version of the schema this instance conforms to",
			"type":"string",
			"enum":["1.0"]},
		"Intent":{
			"description":"How the instance is intended to be used",
			"type":"string",
			"enum":["signed", "cert", "encrypted"]
		}
	}};

var signed_schema = {
	"description":"A signed message",
	"type":"object",
	"extends":base_schema,
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