import json
import Crypto.Cipher
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto import Random
import hashlib
import hmac as hm
import datetime
import dateutil.parser

version = "1.0"

def Hash(alg, data):
    h = hashlib.new(alg)
    h.update(data)
    return h.digest()

def JSONdefault(o):
    return o.JSON()

def JSONdumps(o, indent=None):
    return json.dumps(o, default=JSONdefault, indent=indent)

def get_date(offset=0):
    n = datetime.datetime.utcnow()
    if offset:
        n += datetime.timedelta(offset)
    return n.strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_date(d):
    return dateutil.parser.parse(d, ignoretz=True)

def b64(s):
    return s.encode('base64').replace('\n', '')

def b64d(s):
    return s.decode('base64')

def b64_to_long(b):    
    return bytes_to_long(b64d(b))

def long_to_b64(l):    
    return b64(long_to_bytes(l))

class Certificate(object):
    def __init__(self, name=None, pubkey=None, encoding=None):
        if encoding:
            if encoding[0] != '{':
                encoding = b64d(encoding)
            self.json_ = json.loads(encoding)
            self.username_ = self.json_['Name']
            self.pubkey_ = self.json_['PublicKey']
        else:
            self.json_ = {}

        if name:
            self.json_['Name'] = name
        if pubkey:
            self.json_['PublicKey'] = pubkey
        if not 'NotBefore' in self.json_:
            self.json_['NotBefore'] = get_date(-1)
        if not 'NotAfter' in self.json_:
            self.json_['NotAfter'] = get_date(1)
        self.json_['Version'] = version
        self.json_['Type'] = 'certificate'

    @property
    def Username(self):
        return self.json_['Name']

    @property
    def Base64(self):
        return b64(json.dumps(self.json_))

    @property
    def Pubkey(self):
        return self.json_['PublicKey']

    @property
    def NotBefore(self):
        return parse_date(self.json_['NotBefore'])

    @property
    def NotAfter(self):
        return parse_date(self.json_['NotAfter'])

    def Validate(self):
        n = datetime.datetime.utcnow()
        if self.NotBefore > n:
            return False
        if self.NotAfter < n:
            return False
        if len(self.Username) == 0:
            return False
        if not self.Pubkey:
            return False
        return True

    def JSON(self):
        return self.json_

    def __str__(self):
        return JSONdumps(self.json_, indent=2)

class PublicKey(object):
    def __init__(self, encoding=None, key=None):
        if encoding:
            if encoding[0] != '{':
                encoding = b64d(encoding)
            parsed = json.loads(encoding)
            n = long(parsed['n'])
            e = long(parsed['e'])
            self.key = RSA.construct((n, e))
        if key:
            self.key = key
        self.json_ = {"Algorithm": "RSA",
                      "RsaExponent": long_to_b64(key.e),
                      "RsaModulus": long_to_b64(key.n)}

    def verify(self, signature, signature_algorithm, digest_algorithm, signed_data):
        dig = Hash(digest_algorithm, signed_data)
        return self.key.verify(dig, (b64_to_long(signature), 1))

    def encrypt(self, plaintext):
        return self.key.encrypt(plaintext, None)[0]

    def getBase64(self):
        return b64(self.encoding_)

    def JSON(self):
        return self.json_

    def __str__(self):
        return JSONdumps(self, indent=2)

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
        return PublicKey(key=self.priv.publickey())
    Pubkey = property(getPubkey)

    def getPrivkey(self):
        jpriv = json.dumps(self.priv.key.__dict__)
        return PrivateKey(b64(jpriv))
    Privkey = property(getPrivkey)

    def getCertificate(self):
        return Certificate(name=self.name, pubkey=self.Pubkey)
    Certificate = property(getCertificate)

def getCipherAlgorithm(algorithm):
    (name, size, mode) = algorithm.split("-")
    if not name in Crypto.Cipher.__all__:
        raise Exception("Unknown algorithm", name)
    __import__("Crypto.Cipher." + name)
    alg = Crypto.Cipher.__dict__[name]
    m = alg.__dict__["MODE_" + mode]
    return (alg, int(size), m)

def pad(data, k):
    # See RFC 5652 Section 6.3
    v = k - (len(data) % k)
    return data + (chr(v) * v)

def unpad(data):
    # See RFC 5652 Section 6.3
    s = ord(data[-1])
    return data[:-s]

def symmetricEncrypt(key, iv, algorithm, data):
    (alg, size, mode) = getCipherAlgorithm(algorithm)
    assert(len(key) * 8 == size)
    cipher = alg.new(key, mode, iv)
    return cipher.encrypt(pad(data, alg.block_size))

def symmetricDecrypt(key, iv, algorithm, data):
    (alg, size, mode) = getCipherAlgorithm(algorithm)
    assert(len(key) * 8 == size)
    cipher = alg.new(key, mode, iv)
    return unpad(cipher.decrypt(data))

def generateIV(algorithm):
    (alg, size, mode) = getCipherAlgorithm(algorithm)
    return generateRandom(alg.block_size)

class HashHolder:
    def __init__(self, name):
        self.name_ = name

    def __call__(self):
        (hm, name) = self.name_.split("-")
        return hashlib.new(name)

class HashMeta(type):
    def __new__(cls, name):
        return HashHolder(name)

def hmac(key, algorithm, data):
    h = hm.new(key, data, HashMeta(algorithm))
    return h.digest()

rand = Random.new()
def generateRandom(octets):
    return rand.read(octets)

def kdf(k, use):
    return use + ":" + k

if __name__ == '__main__':
    pair = KeyPair("joe", 384)
    priv = pair.Privkey
    cert = pair.Certificate
    print cert
    print cert.Validate()
    pub = cert.Pubkey
    ciphertext = pub.encrypt("foo")
    print priv.decrypt(ciphertext)
