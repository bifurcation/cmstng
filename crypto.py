import json
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import keyczar.keys
import keyczar.util
import hashlib

def Hash(alg, data):
    h = hashlib.new(alg)
    h.update(data)
    return h.digest();

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
        self.encoding_ = encoding.decode('base64')
        parsed = json.loads(self.encoding_)
        n = long(parsed['n'])
        e = long(parsed['e'])
        self.key = RSA.construct((n, e))

    def verify(self, signature, signature_algorithm, digest_algorithm, signed_data):
        dig = Hash(digest_algorithm, signed_data)
        return self.key.verify(dig, (keyczar.util.BytesToLong(signature.decode('base64')), 1))

    def encrypt(self, plaintext):
        return self.key.encrypt(plaintext, None)[0]

    def getBase64(self):
        return self.encoding_.encode("base64")

    def __str__(self):
        return self.encoding_

class PrivateKey(object):
    def __init__(self, encoding):
        self.encoding_ = encoding.decode('base64')
        parsed = json.loads(self.encoding_)
        n = long(parsed['n'])
        e = long(parsed['e'])
        d = long(parsed['d'])
        p = long(parsed['p'])
        q = long(parsed['q'])
        self.key = RSA.construct((n, e, d, p, q))

    def sign(self, digest_algorithm, signed_data):
        dig = Hash(digest_algorithm, signed_data)
        sig = self.key.sign(dig, None)[0]
        sig2 = keyczar.util.BigIntToBytes(sig)
        print keyczar.util.BytesToLong(sig2) == sig
        return sig2.encode('base64')

    def decrypt(self, ciphertext):
        return self.key.decrypt(ciphertext)

    def getAlgorithm(self):
        return "RSA-PKCS1-1.5"

class KeyPair(object):
    def __init__(self, size=1024):
        self.priv = keyczar.keys.GenKey(keyczar.keyinfo.RSA_PRIV, size)

    def getPubkey(self):
        jpub = json.dumps(self.priv.public_key.key.key.__dict__)
        return PublicKey(jpub.encode('base64'))

    def getPrivkey(self):
        jpriv = json.dumps(self.priv.key.key.__dict__)
        return PrivateKey(jpriv.encode('base64'))

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
