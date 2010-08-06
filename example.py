import datetime
import crypto
from crypto import b64, b64d, get_date, JSONdumps

# Version
version = "1.0"

# The interior message we want to protect
message_text = "This is a test message"
inner_message = {
    'ContentType':"text/plain",
    'Data': message_text
    }

def sign_message(msg, signer_certs, signer_priv, digest_algorithm="SHA1"):
    msg['date'] = get_date()
    msg_b64 = b64(JSONdumps(msg))

    username = signer_certs[0].Username
    signature = signer_priv.sign(digest_algorithm, msg_b64)

    pkix_chain = []
    for cert in signer_certs:
        pkix_chain.append(cert)
            
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
#        for cert in signature['PkixChain']:
#            pkix_chain.append(crypto.Certificate(encoding=cert))
        pkix_chain = signature['PkixChain']
        # TODO: Verify the cert chain


        if pkix_chain[0].Username != signature['Signer']:
            raise Exception("Mismatched usernames: %s != %s"%(pkix_chain[0].Username(), signature['Signer']))
            
        return pkix_chain[0].Pubkey.verify(signature['Value'],
                                           signature['SignatureAlgorithm'],
                                           signature['DigestAlgorithm'],
                                           msg['SignedData'])

    except KeyError, e:
        raise Exception("Malformed message, missing key: %s",str(e))



def encrypt_message(msg, recipient_cert, encryption_algorithm, integrity_algorithm):
    sk = crypto.generateSessionKey(encryption_algorithm)
    key_exchange = recipient_cert.Pubkey.encrypt(sk)    
    
    mek = crypto.kdf(sk, encryption_algorithm)
    mik = crypto.kdf(sk, integrity_algorithm)
    iv = crypto.generateIV(encryption_algorithm)
    ciphertext = crypto.symmetricEncrypt(mek, iv, encryption_algorithm, JSONdumps(msg))
    mac = crypto.hmac(mik, integrity_algorithm, ciphertext)

    emsg = {
        'Version':version,
        'Type':'encryption',
        'Recipients':[
            {
                'Name':recipient_cert.Username,
                'EncryptionAlgorithm':"RSA-PKCS1-1.5",
                # TODO: hash of cert
                "EncryptionKey":b64(key_exchange)
                }
            ],
        "Encryption":{"Algorithm":encryption_algorithm, "IV":b64(iv)},
        "Integrity":{"Algorithm":integrity_algorithm, "Value":b64(mac) },
        "EncryptedData":b64(ciphertext)
        }

    return emsg
    
def decrypt_message(msg, privKey):
    rcpt = msg['Recipients'][0]
    sk = b64d(rcpt['EncryptionKey'])
    sk = privKey.decrypt(sk)

    ciphertext = b64d(msg['EncryptedData'])

    enc = msg['Encryption']
    iv = b64d(enc['IV'])
    encryption_algorithm = enc['Algorithm']
    mek = crypto.kdf(sk, encryption_algorithm)
    plaintext = crypto.symmetricDecrypt(mek, iv, encryption_algorithm, ciphertext)

    integ = msg['Integrity']
    val = b64d(integ['Value'])
    integrity_algorithm = integ['Algorithm']
    mik = crypto.kdf(sk, integrity_algorithm)
    mac = crypto.hmac(mik, integrity_algorithm, ciphertext)
    if mac != val:
        raise Exception("Invalid HMAC")
    return plaintext

if __name__ == '__main__':
    ekr_kp = crypto.KeyPair('ekr@rtfm.com')
    ekr_cert = ekr_kp.Certificate
    ekr_certs = [ ekr_cert, ]
    ekr_priv = ekr_kp.Privkey

    # Sign a message
    signed = sign_message(inner_message, ekr_certs, ekr_priv)
    print "***** Signed message ****"
    print JSONdumps(signed, indent=2)
    print "*****"


    # Verify a message
    result = verify_message(signed)
    if result != True:
        print "Verification failed"
    else:
        print "Verification succceeded"
        
    # Encrypt a message
    encrypted = encrypt_message(inner_message, ekr_cert, "AES-256-CBC", "HMAC-SHA1")
    print JSONdumps(encrypted, indent=2)

    decrypted = decrypt_message(encrypted, ekr_priv)
    print decrypted
