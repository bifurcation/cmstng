import json
import datetime
import base64

# VErsion
version = "1.0"

# The interior message we want to protect
message_text = "This is a test message"

n = datetime.datetime.utcnow()
date = .strftime("%Y-%m-%dT%H:%M:%SZ")


inner_message = {
    'ContentType':"text/plain",
    'Data': message_text
    }


def sign_message(msg, signer_cert, signer_priv, digest_algorithm="SHA1"):
    msg['date'] = date
    msg_b64 = base64.b64encode(json.dumps(msg))

    username = signer_certs[0].getUsername()
    signature = signer_priv.sign(msg_b64)

    pkix_chain = []
    for cert in signer_certs:
        pkix_chain.append(cert.getBase64())
            
    smsg = {
	"Version":version,
        "Signature":{
            "DigestAlgorithm":digest_algorithm,
            "SignatureAlgorithm":signer_priv.getAlgorithm(),
            "PkixChain":pkix_chain
            }
        "SignedData":msg_b64
        }

    
    


    



    


