from crypto import *


# The interior message we want to protect
message_text = "This is a test message"
inner_message = {
    'ContentType':"text/plain",
    'Data': message_text
    }

def sign_message(msg, signer_certs, signer_priv, digest_algorithm="SHA1"):
    sig = Signed(data=message_text)
    sig.sign(signer_priv, signer_certs, digest_algorithm)
    return sig

def verify_message(msg):
    return msg.verify(True)

def encrypt_message(msg, recipient_cert, encryption_algorithm, integrity_algorithm):
    e = Encrypted(msg)
    e.encrypt([recipient_cert,], encryption_algorithm, integrity_algorithm)
    return e
    
def decrypt_message(msg, privKey, name):
    d = msg.decrypt(privKey, name=name)
    return d.Data

if __name__ == '__main__':
    ekr_kp = PrivateKey()
    ekr_cert = Certificate('ekr@rtfm.com', ekr_kp.PublicKey, validityDays=7)

    # Sign a message
    signed = sign_message(inner_message, ekr_cert, ekr_kp)
    print "***** Signed message ****"
    print JSONdumps(signed, indent=2)
    print "*****"

    # Verify a message
    result = verify_message(signed)
    if not result:
        print "Verification failed"
    else:
        print "Verification succceeded"
        
    # Encrypt a message
    encrypted = encrypt_message(message_text, ekr_cert, "AES-256-CBC", "HMAC-SHA1")
    print JSONdumps(encrypted, indent=2)

    decrypted = decrypt_message(encrypted, ekr_kp, ekr_cert.Name)
    print decrypted
