var msg = { 
	'Version':'1.0',
	'Signature':{
		'Value':b64(sig),
		'DigestAlgorithm':'SHA-1',
		'SignatureAlgorithm':'RSA-PKCS1-1.5',
		'Signer':'hildjj@jabber.org', // XOR certs
		'PKIXChain':[
			b64(certMe),
			b64(certSigner),
			b64(certCA)
			// ...
		]
	},
	'SignedData':b64({
						 'ContentType': 'text/plain', 
						 'Date': '2010-08-01T11:42:27Z',
						 'Data': 'foo'
					 })};


