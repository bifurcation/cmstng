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



def encrypt_message(msg, recipient_cert, encryption_algorithm, integrity_algorithm):
    sk = crypto.generateRandom(32);
    key_exchange = recipient_cert.getPubkey().encrypt(sk)    
    
    mek = crypto.kdf(sk, encryption_algorithm)
    mik = crypto.kdf(sk, integrity_algorithm)
    iv = crypto.generateIV(encryption_algorithm),
    ciphertext = crypto.symmetricEncrypt(mek, iv, encryption_algorithm, json.dumps(msg)).encode("base64")
    mac = crypto.hmac(mik, ciphertext)

    emsg = {
        'Version':version,
        'Recipients':[
            {
                'Name':recipient_cert.getUsername(),
                'EncryptionAlgorithm':"RSA-PKCS1-1.5",
                # TODO: hash of cert
                "EncryptionKey":sk.encode("base64")
                }
            ],
        "Encryption":{"Algorithm":encryption_algorithm, "IV":iv},
        "Integrity":{"Algorithm":integrity_algorithm, "Value":mac },
        "EncryptedData":ciphertext
        }

    return emsg
    
    
if __name__ == '__main__':
    ekr_cert_json = {
        'username':'ekr@rtfm.com',
        'pubkey':crypto.PublicKey('{"e": 65537, "n": 100921537266968955102201693205288304972054001556332353053671517819243873231880334610649036435245374797399375167191364972905022277612584062488933250439884335439025806639083349930004418675637027797998397047346143039377436215292366778478997641680725594674785312825202217981566537952094713057006951077207568999867}'.encode('base64')).getBase64()
        }
                    
    ekr_certs = [ crypto.Certificate( json.dumps(ekr_cert_json).encode("base64")) ]
    ekr_priv = crypto.PrivateKey('{"e": 65537, "d": 33798097257052270115860090673507602080147721533765391837007834858122351186250661214802707656450028015522857106207426010121296808658330332537453758650145428472993833806633953842179396995447848887937100323988639000108565504011411639667396486631850050180587826564336578838007439576584826631612328961936071581793, "n": 100921537266968955102201693205288304972054001556332353053671517819243873231880334610649036435245374797399375167191364972905022277612584062488933250439884335439025806639083349930004418675637027797998397047346143039377436215292366778478997641680725594674785312825202217981566537952094713057006951077207568999867, "q": 12063139544877603977259423172439767670516730150044705712897042467876532842138176201432587537328049537297448093629980758652383717839281797146818609114139357, "p": 8366108747355366313031666031141525195053788123805390410361484090926858855575746473831455519379315006335518035945058102692952619639268376507230240320941431, "u": 9704211950479573482348599681140291121645411262415700389949912458888322113516760704948705146368381067615971014071973973503636084600448285864487071372802148}'.encode('base64'))

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
        



    


