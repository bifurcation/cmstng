import json
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import keyczar.keys
import keyczar.util

class Certificate(object):
    def __init__(self, encoding):
        self.encoding_ = encoding.decode("base64")
        parsed=json.loads(self.encoding_)
        self.username_ = parsed['username']
        self.pubkey_ = parsed['pubkey']

    def getUsername(self):
        return self.username_

    def getBase64(self):
        return self.encoding_.encode("base64")

    def getPubkey(self):
        return PublicKey(self.pubkey_)


class PublicKey(object):
    def __init__(self, encoding):
        self.encoding_ = encoding
        parsed = json.loads(self.encoding_)
        n = long(parsed['n'])
        e = long(parsed['e'])
        self.key = RSA.construct((n, e))

    def verify(self, signature, signature_algorithm, digest_algorithm, signed_data):
        return True

    def encrypt(self, plaintext):
        return self.key.encrypt(plaintext, None)[0]

    def getBase64(self):
        return self.encoding_.encode("base64")

    def __str__(self):
        return self.encoding_

class PrivateKey(object):
    def __init__(self, encoding):
        self.encoding_ = encoding
        parsed = json.loads(self.encoding_)
        n = long(parsed['n'])
        e = long(parsed['e'])
        d = long(parsed['d'])
        p = long(parsed['p'])
        q = long(parsed['q'])
        self.key = RSA.construct((n, e, d, p, q))

    def sign(self, digest_algorithm, signed_data):
        return "Signature" + "+" + digest_algorithm

    def decrypt(self, ciphertext):
        return self.key.decrypt(ciphertext)

    def getAlgorithm(self):
        return "RSA-PKCS1-1.5"

    

class KeyPair(object):
    def __init__(self, size=1024):
        self.priv = keyczar.keys.GenKey(keyczar.keyinfo.RSA_PRIV, size)

    def getPubkey(self):
        jpub = json.dumps(self.priv.public_key.key.key.__dict__)
        return PublicKey(jpub)

    def getPrivkey(self):
        jpriv = json.dumps(self.priv.key.key.__dict__)
        return PrivateKey(jpriv)

def symmetricEncrypt(key, iv, algorithm, data):
    return data

    def __str__(self):
        return self.encoding_

def generateIV(algorithm):
    return "IV12345"

def hmac(key, algorithm, data):
    return "MAC12345678"

def generateRandom(bits):
    return "KEY1234567890123456"

def kdf(k, use):
    return use + ":" + k


if __name__ == '__main__':
    pair = KeyPair(384)
    priv = pair.getPrivkey()
    pub = pair.getPubkey()
    ciphertext = pub.encrypt("foo")
    print priv.decrypt(ciphertext)
