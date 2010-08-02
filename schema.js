var signed_schema = {
	"description":"A signed message",
	"type":"object",
	"properties": {
		"Version": {
			"type":"string",
			"enum":["1.0"]},
		"Signature": {
			"type":"object",
			"properties": {
				"Value": {"type":"string"},
				"DigestAlgorithm": {
					"type":"string",
					"enum":["SHA1", "SHA256"] },
				"SignatureAlgorithm": {
					"type":"string",
					"enum":["RSA-PKCS1-1.5"] },
				"Signer": {
					"type":"string",
					"format":"email" },
				"PkixChain": {
					"type":"array",
					"minItems":1,
					"items": {
						"type":"string" } }
			}}}};