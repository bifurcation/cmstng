import json
import Crypto.Cipher
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto import Random
import hashlib
import hmac as HMAC
import datetime
import dateutil.parser
import math
import struct

version = "1.0"

def Hash(alg, data):
    "Hash the data according to the given algorithm.  Example algorithm: 'SHA1'"
    h = hashlib.new(alg)
    h.update(data)
    return h.digest()

def get_date(offset=0):
    "Get the current date/time, offset by the number of days specified, with second precision"
    n = datetime.datetime.utcnow()
    if offset:
        n += datetime.timedelta(offset)
        
    return n - datetime.timedelta(microseconds=n.microsecond)

def _JSONdefault(o):
    """Turn an object into JSON.  
    Dates and instances of classes derived from CryptBase get special handling"""
    if isinstance(o, datetime.datetime):
        return o.strftime("%Y-%m-%dT%H:%M:%SZ")
    return o.JSON()

def JSONdumps(o, indent=None):
    "Dump crypto objects to string"
    return json.dumps(o, default=_JSONdefault, indent=indent)

def _JSONobj(d):
    "Turn a JSON dictionary into a crypto object"
    t = d.get("Type", None)
    if t:
        cons = {
            "certificate": Certificate,
            "publickey": PublicKey,
            "signed": Signed,
            "signature":  Signature,
            "encrypted":  Encrypted,
            "recipient":  Recipient,
            "encryption": Encryption,
            "integrity":  Integrity,
            "privatekey": PrivateKey,
        }.get(t, None)
        if cons:
            return cons(json=d)
    return d

def JSONloads(s):
    "Load a string as a JSON object, converting to crypto objects as needed"
    return json.loads(s, object_hook=_JSONobj)

def parse_date(d):
    "Parse a string containing an ISO8601 date into a datetime"
    return dateutil.parser.parse(d, ignoretz=True)

def b64(s):
    "Base64 encode, without newlines"
    return s.encode('base64').replace('\n', '')

def b64d(s):
    "Base64 decode"
    return s.decode('base64')

def b64_to_long(b):
    "Turn a base64-encoded byte array into a long"
    return bytes_to_long(b64d(b))

def long_to_b64(l):    
    "Turn a long into a base64-encoded byte array"
    return b64(long_to_bytes(l))

class CryptoException(Exception):
    "All exceptions throw intentionally from this module"
    pass

class Props(object):
    "A decorator that adds a JSON access property for each of the strings that are passed."
    def __init__(self, *args, **kwargs):
        self.args = args
        self.plain = args
        self.date = []
        self.base64 = []
        plain = kwargs.get("plain", [])
        date = kwargs.get("date", [])
        base64 = kwargs.get("base64", [])
        if plain:
            if isinstance(plain, (list, tuple)):
                self.plain += plain
            else:
                self.plain += (plain,)
            self.args += self.plain
        if date:
            if isinstance(date, (list, tuple)):
                self.date = date
            else:
                self.date = (date,)
            self.args += self.date
        if base64:
            if isinstance(base64, (list, tuple)):
                self.base64 = base64
            else:
                self.base64 = (base64,)
            self.args += self.base64

    def __call__(self, cls):
        cls.Props = self.args
        for p in self.plain:
            def g(self, prop=p):
                return self.json_[prop]
            def s(self, x, prop=p):
                self.json_[prop] = x
            def d(self, prop=p):
                del self.json_[prop]
            setattr(cls, p, property(g, s, d))
        for p in self.date:
            def g(self, prop=p):
                d = self.json_[prop]
                if isinstance(d, datetime.datetime):
                    return d
                return parse_date(d)
            def s(self, x, prop=p):
                if isinstance(x, datetime.datetime):
                    self.json_[prop] = x
                else:
                    self.json_[prop] = parse_date(x)
            def d(self, prop=p):
                del self.json_[prop]
            setattr(cls, p, property(g, s, d))
        for p in self.base64:
            def g(self, prop=p):
                return b64d(self.json_[prop])
            def s(self, x, prop=p):
                self.json_[prop] = b64(x)
            def d(self, prop=p):
                del self.json_[prop]
            setattr(cls, p, property(g, s, d))

        return cls

class CryptBase(object):
    """The base class for all crypto objects.  Crypto objects contain
    a dictionary that holds their state in a form easy to be
    translated to JSON.  Getters and setters modify the JSON
    dictionary."""
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

    def JSON(self):
        return self.json_

    @property
    def Base64(self):
        return b64(JSONdumps(self.json_))

    def __cmp__(self, other):
        if self.__class__ != other.__class__:
            return -1
        r = cmp(self.json_["Type"], other.json_["Type"])
        if r:
            return r
        if hasattr(self, "Version") != hasattr(other, "Version"):
            return -1
        if hasattr(self, "Version"):
            r = cmp(self.json_["Version"], other.json_["Version"])
            if r:
                return r

        for p in self.Props:
            x = getattr(self, p)
            y = getattr(other, p)

            # arrays should do this by default, if you ask me
            if isinstance(x, (list, tuple)):
                r = cmp(len(x), len(y))
                if r:
                    return r
                for (xn, yn) in zip(x, y):
                    r = cmp(xn, yn)
                    if r:
                        return r
            else:
                r = cmp(x, y)
                if r:
                    return r
        return 0

    def __str__(self):
        return JSONdumps(self.json_, indent=2)

@Props("Name", "PublicKey", date=("NotBefore", "NotAfter"))
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

    def validate(self):
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

    def hash(self):
        return "TODO:HASH CERTS"

@Props("RsaExponent", "RsaModulus", "Algorithm")
class PublicKey(CryptBase):
    def __init__(self, key=None, json=None):
        super(PublicKey, self).__init__("publickey", json, ver=None)
        if key:
            self.key = key
            self.json_["RsaExponent"] = long_to_b64(key.e)
            self.json_["RsaModulus"] = long_to_b64(key.n)
            self.json_["Algorithm"] = "RSA-PKCS1-1.5"
        else:
            n = b64_to_long(self.json_['RsaModulus'])
            e = b64_to_long(self.json_['RsaExponent'])
            self.key = RSA.construct((n, e))

    def verify(self, signed_data, signature, signature_algorithm="RSA-PKCS1-1.5", digest_algorithm="SHA1"):
        dig = Hash(digest_algorithm, signed_data)
        return self.key.verify(dig, (b64_to_long(signature), 1))

    def encrypt(self, plaintext):
        return self.key.encrypt(plaintext, None)[0]

@Props("PublicKey", "PrivateExponent", "Algorithm")
class PrivateKey(CryptBase):
    def __init__(self, key=None, size=1024, json=None):
        super(PrivateKey, self).__init__("privatekey", json)
        if not json:
            if key:
                self.key = key
            else:
                self.key = RSA.generate(size)
            assert(self.key)
            self.PublicKey = PublicKey(key=self.key.publickey())
            self.PrivateExponent = long_to_b64(self.key.d)
            self.Algorithm = "RSA-PKCS1-1.5"
        else:
            self.key = RSA.construct((self.PublicKey.key.n, 
                                      self.PublicKey.key.e,
                                      b64_to_long(self.PrivateExponent)))

    def sign(self, signed_data, digest_algorithm="SHA1"):
        dig = Hash(digest_algorithm, signed_data)
        sig = self.key.sign(dig, None)[0]
        sig2 = long_to_bytes(sig)
        return b64(sig2)

    def decrypt(self, ciphertext):
        return self.key.decrypt(ciphertext)

@Props("PkixChain", "Signer", "DigestAlgorithm", "SignatureAlgorithm", "Value")
class Signature(CryptBase):
    def __init__(self, certs=None, digest_algorithm=None, sig_algorithm=None, value=None, json=None):
        super(Signature, self).__init__("signature", json, ver=None)
        if certs:
            if not isinstance(certs, (list, tuple)):
                certs = (certs,)
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

        return cert.PublicKey.verify(data, self.Value, self.SignatureAlgorithm, self.DigestAlgorithm)

@Props("Signature", "SignedData")
class Signed(CryptBase):
    def __init__(self, data=None, contentType="text/plain", json=None):
        super(Signed, self).__init__("signed", json)
        if data:
            if not contentType:
                raise CryptoException("Must supply content type with data")
            inner = {
                'ContentType':contentType,
                'Date': get_date(),
                'Data': data
                }
            self.SignedData = b64(JSONdumps(inner))

    def sign(self, key, certs, digest_algorithm="SHA1"):
        val = key.sign(b64d(self.SignedData), digest_algorithm)
        self.Signature = Signature(certs, digest_algorithm, key.Algorithm, val)

    def verify(self):
        # TODO: check dates, nonces, etc?
        return self.Signature.verify(b64d(self.SignedData))

@Props("Name", "EncryptionAlgorithm", "PkixCertificateHash", "EncryptionKey")
class Recipient(CryptBase):
    def __init__(self, cert=None, key=None, json=None):
        super(Recipient, self).__init__("recipient", json, ver=None)
        if cert:
            self.Name = cert.Name
            self.EncryptionAlgorithm = cert.PublicKey.Algorithm
            self.PkixCertificateHash = cert.hash()
        if key:
            self.EncryptionKey = b64(key)

@Props("Algorithm", "IV")
class Encryption(CryptBase):
    def __init__(self, algorithm=None, iv=None, json=None):
        super(Encryption, self).__init__("encryption", json, ver=None)
        if algorithm:
            self.Algorithm = algorithm
        if iv:
            self.IV = b64(iv)

@Props("Algorithm", "Value")
class Integrity(CryptBase):
    def __init__(self, algorithm=None, value=None, json=None):
        super(Integrity, self).__init__("integrity", json, ver=None)
        if algorithm:
            self.Algorithm = algorithm
        if value:
            self.Value = b64(value)

@Props("Recipients", "Encryption", "Integrity", "EncryptedData")
class Encrypted(CryptBase):
    def __init__(self, data=None, contentType="text/plain", json=None):
        super(Encrypted, self).__init__("encrypted", json)
        if data:
            if not contentType:
                raise CryptoException("Must supply content type with data")
            self.inner = {
                'ContentType':"text/plain",
                'Date': get_date(),
                'Data': data
                }
    def encrypt(self, toCerts, encryption_algorithm="AES-256-CBC", integrity_algorithm="HMAC-SHA1"):
        (alg, size, mode) = getAlgorithm(encryption_algorithm)
        iv = generateIV(encryption_algorithm)
        self.Encryption = Encryption(encryption_algorithm, iv)

        sk = generateSessionKey(encryption_algorithm)
        mek = kdf(sk, encryption_algorithm)
        ciphertext = symmetricEncrypt(mek, iv, encryption_algorithm, JSONdumps(self.inner))
        self.EncryptedData = b64(ciphertext)

        rcpts = []
        for c in toCerts:
            key_exchange = c.PublicKey.encrypt(sk)
            r = Recipient(c, key_exchange)
            rcpts.append(r)
        self.Recipients = rcpts

        mik = kdf(sk, integrity_algorithm)
        mac = hmac(mik, integrity_algorithm, ciphertext)
        self.Integrity = Integrity(integrity_algorithm, mac)

    def decrypt(self, privKey, name):
        rcpt = None
        for r in self.Recipients:
            if r.Name == name:
                rcpt = r
                break
        if not rcpt:
            raise CryptoException("Name not found")
        sk = b64d(rcpt.EncryptionKey)
        sk = privKey.decrypt(sk)
        ciphertext = b64d(self.EncryptedData)
        iv = b64d(self.Encryption.IV)
        encryption_algorithm = self.Encryption.Algorithm
        mek = kdf(sk, encryption_algorithm)
        plaintext = symmetricDecrypt(mek, iv, encryption_algorithm, ciphertext)
        res = JSONloads(plaintext)
        dt = res["Date"] = parse_date(res["Date"])
        if dt > get_date(): # TODO: clock skew
            raise CryptoException("Message from the future")

        integrity_algorithm = self.Integrity.Algorithm
        mik = kdf(sk, integrity_algorithm)
        mac = hmac(mik, integrity_algorithm, ciphertext)
        if mac != b64d(self.Integrity.Value):
            raise CryptoException("Invalid HMAC")

        return res

class KeyPair(object):
    def __init__(self, name, size=1024):
        self.name = name
        self.priv = RSA.generate(size)

    @property
    def Pubkey(self):
        return PublicKey(key=self.priv.publickey())

    @property
    def Privkey(self):
        return PrivateKey(key=self.priv)

    def genCertificate(self, validityDays=365):
        return Certificate(name=self.name, pubkey=self.Pubkey, validityDays=validityDays)

__algorithms__ = {
    "AES-256-CBC": (Crypto.Cipher.AES, 256 / 8, Crypto.Cipher.AES.MODE_CBC),
    "AES-128-CBC": (Crypto.Cipher.AES, 128 / 8, Crypto.Cipher.AES.MODE_CBC),
    "HMAC-SHA1":   (hashlib.sha1, 64, None),
    "HMAC-SHA256": (hashlib.sha256, 64, None),
}

def getAlgorithm(algorithm):
    ret = __algorithms__.get(algorithm, None)
    if not ret:
        raise CryptoException("Unknown algorithm: " + algorithm)
    return ret

def pad(data, k):
    # See RFC 5652 Section 6.3
    v = k - (len(data) % k)
    return data + (chr(v) * v)

def unpad(data):
    # See RFC 5652 Section 6.3
    s = ord(data[-1])
    return data[:-s]

def symmetricEncrypt(key, iv, algorithm, data):
    (alg, size, mode) = getAlgorithm(algorithm)
    assert(len(key) == size)
    cipher = alg.new(key, mode, iv)
    return cipher.encrypt(pad(data, alg.block_size))

def symmetricDecrypt(key, iv, algorithm, data):
    (alg, size, mode) = getAlgorithm(algorithm)
    assert(len(key) == size)
    cipher = alg.new(key, mode, iv)
    return unpad(cipher.decrypt(data))

def generateIV(algorithm):
    (alg, size, mode) = getAlgorithm(algorithm)
    return generateRandom(alg.block_size)

def generateSessionKey(algorithm):
    # account for kdf size
    (alg, size, mode) = getAlgorithm(algorithm)
    return generateRandom(size)

def hmac(key, algorithm, data):
    (alg, size, mode) = getAlgorithm(algorithm)
    h = HMAC.new(key, data, alg)
    return h.digest()

def hmac_sha1(key, data):
    h = HMAC.new(key, data, hashlib.sha1)
    return h.digest()

rand = Random.new()
def generateRandom(octets):
    return rand.read(octets)

def kdf(k, use):
    (alg, size, mode) = getAlgorithm(use)
    return PBKDF2_HMAC_SHA1(k, use, 64, size)

def xors(s1, s2):
    "xor 2 strings"
    return ''.join([chr(ord(a) ^ ord(b)) for (a,b) in zip(s1, s2)])

def PBKDF2_HMAC_SHA1(pw, salt, iterations, desired):
    dkLen = desired
    hLen = 20 # len(HMAC-SHA1)
    
    if dkLen > (2**32 - 1) * hLen:
        raise CryptoError("derived key too long")

    l = int(math.ceil(float(dkLen) / float(hLen)))
    r = dkLen - ((l - 1) * hLen)

    def F(P, S, c, i):
        if c < 1:
            raise CryptoError("invalid number of iterations")
        key_one = S + struct.pack("!I", i)
        prev = hmac_sha1(P, key_one)
        acc = prev
        for j in range(1,c):
            prev = hmac_sha1(P, prev)
            acc = xors(acc, prev)
        return acc

    ret = ""
    for i in range(l):
        ret += F(pw, salt, iterations, i + 1)

    return ret[:dkLen]

if __name__ == '__main__':
    pair = KeyPair("joe", 384)
    priv = pair.Privkey
    print priv

    cert = pair.genCertificate(7)
    print cert
    print cert.validate()
    pub = cert.PublicKey
    ciphertext = pub.encrypt("foo")
    print priv.decrypt(ciphertext)

    s = Signed("Foo")
    s.sign(priv, [cert,])
    print s

    print "Verify: " + str(s.verify())

    e = Encrypted("BAR")
    e.encrypt([cert,])
    print e
    print e.decrypt(priv, "joe")
