import json
import datetime
import crypto

# Version
version = "1.0"

# The interior message we want to protect
message_text = "This is a test message"
inner_message = {
    'ContentType':"text/plain",
    'Data': message_text
    }

def b64(s):
    return s.encode('base64').replace('\n', '')

def get_date():
    n = datetime.datetime.utcnow()
    return n.strftime("%Y-%m-%dT%H:%M:%SZ")

def sign_message(msg, signer_certs, signer_priv, digest_algorithm="SHA1"):
    msg['date'] = get_date()
    msg_b64 = b64(json.dumps(msg))

    username = signer_certs[0].getUsername()
    signature = signer_priv.sign(digest_algorithm, msg_b64)

    pkix_chain = []
    for cert in signer_certs:
        pkix_chain.append(cert.getBase64())
            
    smsg = {
        "Version":version,
        "Signature":{
            "DigestAlgorithm":digest_algorithm,
            "SignatureAlgorithm":signer_priv.getAlgorithm(),
            "PkixChain":pkix_chain,
            "Signer":username,
            "Value":signature
            },
        "SignedData":msg_b64
        }

    return smsg

def verify_message(msg):
    try:
        signature = msg['Signature']
        pkix_chain = []
        
        # TODO: Check version

        for cert in signature['PkixChain']:
            pkix_chain.append(crypto.Certificate(encoding=cert))
        # TODO: Verify the cert chain


        if pkix_chain[0].getUsername() != signature['Signer']:
            raise Exception("Mismatched usernames: %s != %s"%(pkix_chain[0].getUsername(), signature['Signer']))
            
        return pkix_chain[0].getPubkey().verify(signature['Value'],
                                                signature['SignatureAlgorithm'],
                                                signature['DigestAlgorithm'],
                                                msg['SignedData'])

    except KeyError, e:
        raise Exception("Malformed message, missing key: %s",str(e))



def encrypt_message(msg, recipient_cert, encryption_algorithm, integrity_algorithm):
    sk = crypto.generateRandom(32);
    key_exchange = recipient_cert.getPubkey().encrypt(sk)    
    
    mek = crypto.kdf(sk, encryption_algorithm)
    mik = crypto.kdf(sk, integrity_algorithm)
    iv = crypto.generateIV(encryption_algorithm),
    ciphertext = b64(crypto.symmetricEncrypt(mek, iv, encryption_algorithm, json.dumps(msg)))
    mac = crypto.hmac(mik, ciphertext)

    emsg = {
        'Version':version,
        'Recipients':[
            {
                'Name':recipient_cert.getUsername(),
                'EncryptionAlgorithm':"RSA-PKCS1-1.5",
                # TODO: hash of cert
                "EncryptionKey":b64(sk)
                }
            ],
        "Encryption":{"Algorithm":encryption_algorithm, "IV":iv},
        "Integrity":{"Algorithm":integrity_algorithm, "Value":mac },
        "EncryptedData":ciphertext
        }

    return emsg
    
    
if __name__ == '__main__':
    ekr_kp = crypto.KeyPair('ekr@rtfm.com')
    ekr_cert = ekr_kp.Certificate
    ekr_certs = [ ekr_cert, ]
    ekr_priv = ekr_kp.Privkey

    # Sign a message
    signed = sign_message(inner_message, ekr_certs, ekr_priv)
    print "***** Signed message ****"
    print json.dumps(signed, indent=2)
    print "*****"


    # Verify a message
    result = verify_message(signed)
    if result != True:
        print "Verification failed"
    else:
        print "Verification succceeded"
        



    


