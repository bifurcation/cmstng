import datetime
import crypto
from crypto import b64, b64d, get_date, version, JSONdumps


# The interior message we want to protect
message_text = "This is a test message"
inner_message = {
    'ContentType':"text/plain",
    'Data': message_text
    }

def sign_message(msg, signer_certs, signer_priv, digest_algorithm="SHA1"):
    sig = crypto.Signed(data=message_text)
    sig.sign(signer_priv, signer_certs, digest_algorithm)
    return sig

def verify_message(msg):
    return msg.verify()

def encrypt_message(msg, recipient_cert, encryption_algorithm, integrity_algorithm):
    e = crypto.Encrypted(msg)
    e.encrypt([recipient_cert,], encryption_algorithm, integrity_algorithm)
    return e
    
def decrypt_message(msg, privKey, name):
    d = msg.decrypt(privKey, name)
    return d["Data"]

if __name__ == '__main__':
    ekr_kp = crypto.KeyPair('ekr@rtfm.com')
    ekr_cert = ekr_kp.Certificate
    ekr_priv = ekr_kp.Privkey
    #ekr_priv = crypto.PrivateKey(size=1024)
    #ekr_cert =  ekr_priv.PublicKey.genCertificate('ekr@rtfm.com')
    ekr_certs = [ ekr_cert, ]

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
    encrypted = encrypt_message(message_text, ekr_cert, "AES-256-CBC", "HMAC-SHA1")
    print JSONdumps(encrypted, indent=2)

    decrypted = decrypt_message(encrypted, ekr_priv, ekr_cert.Name)
    print decrypted
