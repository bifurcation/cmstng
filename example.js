var signed_msg = {  // MIME-Type: application/signed+json
    "Version":"1.0",
    "Signature":{
        "Value":b64(sig),
        "DigestAlgorithm":"SHA-1",
        "SignatureAlgorithm":"RSA-PKCS1-1.5",
        "Signer":"hildjj@jabber.org", // XOR certs
        "PkixChain":[ // RFC 5280
            b64(certMe),
            b64(certSigner),
            b64(certCA)
            // ...
        ],
        "PkixCRL":[  // Leave it out?
        ]
    },
    "SignedData":b64({
                         // TODO: signer name?
                         "ContentType": "text/plain", // MIME type
                         "Date": "2010-08-01T11:42:27Z", // RFC 3339
                         "Data": "foo"
                     })};

var encrypted_msg = {  // MIME-Type: application/encrypted+json
	"Type":"encryption",
    "Version":"1.0",
    "Recipients":[
        {
            "Name":"ekr@rtfm.com",
            "EncryptionAlgorithm":"RSA-PKCS1-1.5",
            "PkixCertificateHash":{
                "Algorithm":"SHA-1",
                "Value":b64(sha1(ekrCert))
            },
            "EncryptionKey":b64(crypt(ekrPub, messageKey))
        },
        {
            "Name":"lisa@rtfm.com",
            "EncryptionAlgorithm":"AES-256-CBC", // RFC 3394?  Needs separate integrity?
            "KeyID":"42",
            "EncryptionKey":b64(crypt(key42, messageKey))
        }
    ],
    "Encryption":{
        "Algorithm":"AES-256-CBC",
        "IV":b64(IV)  // May need integrity IV also
// may need a key expansion transform, may go in alg
    },
    "Integrity":{
        "Algorithm":"HMAC-SHA1",
        "Value":b64(hmac)
    },
    "EncryptedData":b64(crypt({
                         // TODO: signer name?
                         "ContentType": "text/plain", // MIME type
                         "Date": "2010-08-01T11:42:27Z", // RFC 3339
                         "Data": "foo"
                     }))};


var signed_encrypted_msg = {  // MIME-Type: application/encrypted+json
	"Type":"encryption",
    "Version":"1.0",
    "Recipients":[
        {
            "Name":"ekr@rtfm.com",
            "EncryptionAlgorithm":"RSA-PKCS1-1.5",
            "PkixCertificateHash":{
                "Algorithm":"SHA-1",
                "Value":b64(sha1(ekrCert))
            },
            "EncryptionKey":b64(crypt(ekrPub, messageKey))
        },
        {
            "Name":"lisa@rtfm.com",
            "EncryptionAlgorithm":"AES-256-CBC", // RFC 3394?  Needs separate integrity?
            "KeyID":"42",
            "EncryptionKey":b64(crypt(key42, messageKey))
        }
    ],
    "Encryption":{
        "Algorithm":"AES-256-CBC",
        "IV":b64(IV)  // May need integrity IV also
// may need a key expansion transform, may go in alg
    },
    "Integrity":{
        "Algorithm":"HMAC-SHA1",
        "Value":b64(hmac)
    },
    "EncryptedData":b64(crypt({
                                  // TODO: signer name?
                                  "ContentType": "text/plain", // MIME type
                                  "Date": "2010-08-01T11:42:27Z", // RFC 3339
                                  "Data": {  // MIME-Type: application/signed+json
                                      "Version":"1.0",
                                      "Signature":{
                                          "Value":b64(sig),
                                          "DigestAlgorithm":"SHA-1",
                                          "SignatureAlgorithm":"RSA-PKCS1-1.5",
                                          "Signer":"hildjj@jabber.org", // XOR certs
                                          "PkixChain":[ // RFC 5280
                                              b64(certMe),
                                              b64(certSigner),
                                              b64(certCA)
                                              // ...
                                          ],
                                          "PkixCRL":[  // Leave it out?
                                          ]
                                      },
                                      "SignedData":b64({
                                                           // TODO: signer name?
                                                           "ContentType": "text/plain", // MIME type
                                                           "Date": "2010-08-01T11:42:27Z", // RFC 3339
                                                           "Data": "foo"
                                                       })}
                              }))};


