var msg = { 
	'Version':'1.0',
	'Signature':{
		'Value':b64(sig),
		'DigestAlgorithm':'SHA-1',
		'SignatureAlgorithm':'RSA-PKCS1-1.5',
		'Signer':'hildjj@jabber.org', // XOR certs
		'PkixChain':[ // RFC 5280
			b64(certMe),
			b64(certSigner),
			b64(certCA)
			// ...
		],
		'PkixCRL':[  // Leave it out?
		]
	},
	'SignedData':b64({
						 // TODO: signer name?
						 'ContentType': 'text/plain', // MIME type
						 'Date': '2010-08-01T11:42:27Z', // RFC 3339
						 'Data': 'foo'
					 })};


