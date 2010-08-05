import json
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto import Random
import hashlib
import hmac as hm

def Hash(alg, data):
    h = hashlib.new(alg)
    h.update(data)
    return h.digest()

def get_date(offset=0):
    n = datetime.datetime.utcnow()
    if offset:
        n += datetime.timedelta(offset)
    return n.strftime("%Y-%m-%dT%H:%M:%SZ")

def b64(s):
    return s.encode('base64').replace('\n', '')

def b64d(s):
    return s.decode('base64')

class Certificate(object):
    def __init__(self, name=None, pubkey=None, encoding=None):
        if encoding:
            if encoding[0] != '{':
                encoding = b64d(encoding)
            self.json_ = json.loads(encoding)
            self.username_ = self.json_['Name']
            self.pubkey_ = self.json_['pubkey']
        else:
            self.json_ = {}

        if name:
            self.json_['Name'] = name
        if pubkey:
            self.json_['pubkey'] = pubkey.getBase64()
        if not 'NotBefore' in json_:
            json[

    def getUsername(self):
        return self.json_['Name']
    Username = property(getUsername)

    def getBase64(self):
        return b64(json.dumps(self.json_))
    Base64 = property(getBase64)

    def getPubkey(self):
        return PublicKey(self.json_['pubkey'])
    Pubkey = property(getPubkey)
    
    def Validate(self):
        return False

    def __str__(self):
        return json.dumps(self.json_, indent=2)

class PublicKey(object):
    def __init__(self, encoding):
        self.encoding_ = b64d(encoding)
        parsed = json.loads(self.encoding_)
        n = long(parsed['n'])
        e = long(parsed['e'])
        self.key = RSA.construct((n, e))

    def verify(self, signature, signature_algorithm, digest_algorithm, signed_data):
        dig = Hash(digest_algorithm, signed_data)
        return self.key.verify(dig, (bytes_to_long(b64d(signature)), 1))

    def encrypt(self, plaintext):
        return self.key.encrypt(plaintext, None)[0]

    def getBase64(self):
        return b64(self.encoding_)

    def __str__(self):
        return self.encoding_

class PrivateKey(object):
    def __init__(self, encoding):
        self.encoding_ = b64d(encoding)
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
        sig2 = long_to_bytes(sig)
        return b64(sig2)

    def decrypt(self, ciphertext):
        return self.key.decrypt(ciphertext)

    def getAlgorithm(self):
        return "RSA-PKCS1-1.5"

class KeyPair(object):
    def __init__(self, name, size=1024):
        self.name = name
        self.priv = RSA.generate(size)

    def getPubkey(self):
        jpub = json.dumps(self.priv.publickey().key.__dict__)
        return PublicKey(b64(jpub))
    Pubkey = property(getPubkey)

    def getPrivkey(self):
        jpriv = json.dumps(self.priv.key.__dict__)
        return PrivateKey(b64(jpriv))
    Privkey = property(getPrivkey)

    def getCertificate(self):
        return Certificate(name=self.name, pubkey=self.Pubkey)
    Certificate = property(getCertificate)

def symmetricEncrypt(key, iv, algorithm, data):
    return data

    def __str__(self):
        return self.encoding_

def generateIV(algorithm):
    return "IV12345"

class HashHolder:
    def __init__(self, name):
        self.name_ = name

    def __call__(self):
        return hashlib.new(self.name_)

class HashMeta(type):
    def __new__(cls, name):
        return HashHolder(name)

def hmac(key, algorithm, data):
    h = hm.new(key, data, HashMeta(algorithm))
    return h.digest()

rand = Random.new()
def generateRandom(bits):
    return rand(bits / 8)

def kdf(k, use):
    return use + ":" + k

if __name__ == '__main__':
    pair = KeyPair("joe", 384)
    priv = pair.Privkey
    cert = pair.Certificate
    pub = cert.Pubkey
    print cert
    ciphertext = pub.encrypt("foo")
    print priv.decrypt(ciphertext)
