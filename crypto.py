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

def get_date(offset=0):
    n = datetime.datetime.utcnow()
    if offset:
        n += datetime.timedelta(offset)
    return n
    #return n.strftime("%Y-%m-%dT%H:%M:%SZ")

def JSONdefault(o):
    if isinstance(o, datetime.datetime):
        return o.strftime("%Y-%m-%dT%H:%M:%SZ")
    return o.JSON()

def JSONdumps(o, indent=None):
    return json.dumps(o, default=JSONdefault, indent=indent)

def JSONobj(d):
    t = d.get("Type", None)
    if t:
        cons = {
            "certificate": Certificate,
            "publickey": PublicKey,
            "signed": Signed,
            "signature": Signature
        }.get(t, None)
        if cons:
            return cons(json=d)
    return d

def JSONloads(s):
    return json.loads(s, object_hook=JSONobj)

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

class CryptoException(Exception):
    pass

class CryptBase(object):
    def __init__(self, objectType, json=None, ver=version):
        if json:
            if objectType:
                # I *think* this is always a programming error
                assert(json["Type"] == objectType)
            if ver:
                if json.get("Version", None) != ver:
                    raise CryptoException("Invalid version")
            self.json_ = json
        elif objectType:
            self.json_ = {"Type":objectType}
            if ver:
                self.json_["Version"] = ver
        else:
            self.json_ = {}

    @classmethod
    def setProps(cls, *props):
        for p in props:
            def g(self, prop=p):
                return self.json_[prop]
            def s(self, v, prop=p):
                self.json_[prop] = v
            def d(self, prop=p):
                del self.json_[prop]
            setattr(cls, p, property(g, s, d))

    def JSON(self):
        return self.json_

    @property
    def Base64(self):
        return b64(JSONdumps(self.json_))

    def __str__(self):
        return JSONdumps(self.json_, indent=2)

class Certificate(CryptBase):
    def __init__(self, name=None, pubkey=None, validityDays=None, json=None):
        super(Certificate, self).__init__("certificate", json)

        if name:
            self.Name = name
        if pubkey:
            self.PublicKey = pubkey
        if validityDays:
            self.NotBefore = get_date()
            self.NotAfter = get_date(validityDays)

    def Validate(self):
        n = datetime.datetime.utcnow()
        if self.NotBefore > n:
            return False
        if self.NotAfter < n:
            return False
        if len(self.Name) == 0:
            return False
        if not self.PublicKey:
            return False
        if self.json_['Version'] != version:
            return False
        return True
Certificate.setProps("Name", "PublicKey", "NotBefore", "NotAfter")

class PublicKey(CryptBase):
    def __init__(self, key=None, json=None):
        super(PublicKey, self).__init__("publickey", json, ver=None)
        if key:
            self.key = key
            self.json_["RsaExponent"] = long_to_b64(key.e)
            self.json_["RsaModulus"] = long_to_b64(key.n)
            self.json_["Algorithm"] = "RSA"
        else:
            n = b64_to_long(self.json_['RsaModulus'])
            e = b64_to_long(self.json_['RsaExponent'])
            self.key = RSA.construct((n, e))

    def verify(self, signature, signature_algorithm, digest_algorithm, signed_data):
        dig = Hash(digest_algorithm, signed_data)
        return self.key.verify(dig, (b64_to_long(signature), 1))

    def encrypt(self, plaintext):
        return self.key.encrypt(plaintext, None)[0]
PublicKey.setProps("RsaExponent", "RsaModulus", "Algorithm")

class Signature(CryptBase):
    def __init__(self, certs=None, digest_algorithm=None, sig_algorithm=None, value=None, json=None):
        super(Signature, self).__init__("signature", json, ver=None)
        if certs:
            self.PkixChain = certs
            self.Signer = certs[0].Name
        if digest_algorithm:
            self.DigestAlgorithm = digest_algorithm
        if sig_algorithm:
            self.SignatureAlgorithm = sig_algorithm
        if value:
            self.Value = value

    def verify(self, data):
        # TODO: validate certificate chain
        if len(self.PkixChain) == 0:
            return False

        cert = self.PkixChain[0]
        if cert.Name != self.Signer:
            return False

        return cert.PublicKey.verify(self.Value, self.SignatureAlgorithm, self.DigestAlgorithm, data)

Signature.setProps("PkixChain", "Signer", "DigestAlgorithm", "SignatureAlgorithm", "Value")

class Signed(CryptBase):
    def __init__(self, data=None, contentType="text/plain", json=None):
        super(Signed, self).__init__("signed", json)
        if data:
            if not contentType:
                raise CryptoException("Must supply content type with data")
            inner = {
                'ContentType':"text/plain",
                'Date': get_date(),
                'Data': data
                }
            self.SignedData = b64(JSONdumps(inner))

    def sign(self, key, certs, digest_algorithm="SHA1"):
        val = key.sign(digest_algorithm, b64d(self.SignedData))
        self.Signature = Signature(certs, digest_algorithm, key.Algorithm, val)

    def verify(self):
        return self.Signature.verify(b64d(self.SignedData))

Signed.setProps("Signature", "SignedData")

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

    @property
    def Algorithm(self):
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
        return Certificate(name=self.name, pubkey=self.Pubkey, validityDays=7)
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

def generateSessionKey(algorithm):
    # account for kdf size
    (alg, size, mode) = getCipherAlgorithm(algorithm)
    return generateRandom((size/8) - len(algorithm) - 1)

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
    pub = cert.PublicKey
    ciphertext = pub.encrypt("foo")
    print priv.decrypt(ciphertext)

    s = Signed("Foo")
    s.sign(priv, [cert,])
    print s

    print "Verify: " + str(s.verify())
