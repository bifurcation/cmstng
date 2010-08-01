import json
import datetime
import base64
import crypto

# VErsion
version = "1.0"

# The interior message we want to protect
message_text = "This is a test message"
inner_message = {
    'ContentType':"text/plain",
    'Data': message_text
    }


def get_date():
    n = datetime.datetime.utcnow()
    return n.strftime("%Y-%m-%dT%H:%M:%SZ")

def sign_message(msg, signer_certs, signer_priv, digest_algorithm="SHA1"):
    msg['date'] = get_date()
    msg_b64 = base64.b64encode(json.dumps(msg))

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
            pkix_chain.append(crypto.Certificate(cert))
        # TODO: Verify the cert chain


        if pkix_chain[0].getUsername() != signature['Signer']:
            raise Exception("Mismatched usernames: %s != %s"%(pkix_chain[0].getUsername(), signature['Signer']))

        return pkix_chain[0].getPubkey().verify(signature['Value'],
                                                signature['SignatureAlgorithm'],
                                                signature['DigestAlgorithm'],
                                                msg['SignedData'])

    except KeyError, e:
        raise Exception("Malformed message, missing key: %s",str(e))


    
if __name__ == '__main__':
    ekr_cert_json = {
        'username':'ekr@rtfm.com',
        'pubkey':crypto.PublicKey("EKRPub").getBase64()
        }
                    
    ekr_certs = [ crypto.Certificate( json.dumps(ekr_cert_json).encode("base64")) ]
    ekr_priv = crypto.PrivateKey("EKRPriv")

    # Sign a message
    signed = sign_message(inner_message, ekr_certs, ekr_priv)
    print "***** Signed message ****"
    print json.dumps(signed)
    print "*****"


    # Verify a message
    result = verify_message(signed)
    if result != True:
        print "Verification failed"
    else:
        print "Verification succceeded"
        



    


