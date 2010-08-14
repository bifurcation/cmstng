from crypto_utils import *
import json

version = "1.0"

def _JSONdefault(o):
    """Turn an object into JSON.  
    Dates and instances of classes derived from CryptBase get special handling"""
    if isinstance(o, datetime.datetime):
        return fmt_date(o)
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
            "encrypted":   Encrypted,
            "encryption":  Encryption,
            "inner":       InnerMessage,
            "integrity":   Integrity,
            "privatekey":  PrivateKey,
            "publickey":   PublicKey,
            "recipient":   Recipient,
            "signature":   Signature,
            "signed":      Signed,
        }.get(t, None)
        if cons:
            return cons(json=d)
    return d

def JSONloads(s):
    "Load a string as a JSON object, converting to crypto objects as needed"
    return json.loads(s, object_hook=_JSONobj)

class CryptoException(Exception):
    "All exceptions throw intentionally from this module"
    pass

class Props(object):
    """A decorator that adds a JSON access property for each of the strings that are passed.
Each property can have a type of plain, date, base64, or long.  Types
other than plain case encoding to happen on set, and decoding to
happen on get.  The default type is plain."""
    def __init__(self, *args, **kwargs):
        self.map = {}
        for t in args:
            self.map[t] = "plain"
        for t in ("plain", "date", "base64", "long"):
            a = kwargs.get(t, None)
            if a:
                if isinstance(a, (list, tuple)):
                    for b in a:
                        self.map[b] = t
                else:
                    self.map[a] = t

    def __call__(self, cls):
        cls.Props = self.map.keys()
        decode = {"plain": lambda x: x,
                  "date": parse_date,
                  "base64": b64d,
                  "long": b64_to_long}
        encode = {"plain": lambda x: x,
                  "date": fmt_date,
                  "base64": b64,
                  "long": long_to_b64}
        for prop,typ in self.map.iteritems():
            def g(self, p=prop, d=decode[typ]):
                return d(self.json_[p])
            def s(self, x, p=prop, e=encode[typ]):
                self.json_[p] = e(x)
            def d(self,  p=prop, t=typ):
                del self.json_[p]
            setattr(cls, prop, property(g, s, d))

        return cls

class CryptBase(object):
    """The base class for all crypto objects.  Crypto objects contain
    a dictionary that holds their state in a form easy to be
    translated to JSON.  Getters and setters modify the JSON
    dictionary."""
    def __init__(self, objectType, json=None):
        if json:
            if objectType:
                # I *think* this is always a programming error
                assert(json["Type"] == objectType)
            self.json_ = json
        elif objectType:
            self.json_ = {"Type":objectType}
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

@Props("Version")
class CryptVersion(CryptBase):
    def __init__(self, objectType, json=None, ver=version):
        super(CryptVersion, self).__init__(objectType, json)
        if json:
            if json.get("Version", None) != ver:
                raise CryptoException("Invalid version")
        elif objectType:
            self.json_["Version"] = ver

    def __cmp__(self, other):
        r = super(CryptVersion, self).__cmp__(other)
        if r:
            return r
        r = cmp(self.Version, other.Version)
        if r:
            return r

        return 0

@Props("Name", "PublicKey", date=("NotBefore", "NotAfter"))
class Certificate(CryptVersion):
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

@Props("Algorithm", long=("RsaExponent", "RsaModulus"))
class PublicKey(CryptBase):
    def __init__(self, key=None, json=None):
        super(PublicKey, self).__init__("publickey", json)
        if key:
            self.key = key
            self.RsaExponent = key.e
            self.RsaModulus = key.n
            self.Algorithm = "RSA-PKCS1-1.5"
        else:
            n = self.RsaModulus
            e = self.RsaExponent
            self.key = RSA.construct((n, e))

    def verify(self, signed_data, signature, signature_algorithm="RSA-PKCS1-1.5", digest_algorithm="SHA1"):
        dig = Hash(digest_algorithm, signed_data)
        return self.key.verify(dig, (signature, 1))

    def encrypt(self, plaintext):
        # size is keysize_in_bits-1 for some reason.
        padded = pad_1_5(plaintext, (self.key.size() + 1)/8)
        ret = self.key.encrypt(padded, None)
        return ret[0]

    def genCertificate(self, name, validityDays=365):
        return Certificate(name=name, pubkey=self, validityDays=validityDays)

@Props("PublicKey", "Algorithm", long="PrivateExponent")
class PrivateKey(CryptVersion):
    def __init__(self, key=None, size=1024, json=None):
        super(PrivateKey, self).__init__("privatekey", json)
        if not json:
            if key:
                self.key = key
            else:
                self.key = RSA.generate(size)
            assert(self.key)
            self.PublicKey = PublicKey(key=self.key.publickey())
            self.PrivateExponent = self.key.d
            self.Algorithm = "RSA-PKCS1-1.5"
        else:
            self.key = RSA.construct((self.PublicKey.key.n, 
                                      self.PublicKey.key.e,
                                      self.PrivateExponent))

    def sign(self, signed_data, digest_algorithm="SHA1"):
        dig = Hash(digest_algorithm, signed_data)
        return self.key.sign(dig, None)[0]

    def decrypt(self, ciphertext):
        plain = self.key.decrypt(ciphertext)
        return unpad_1_5(plain)

@Props("PkixChain", "Signer", "DigestAlgorithm", "SignatureAlgorithm", long="Value")
class Signature(CryptBase):
    def __init__(self, certs=None, digest_algorithm=None, sig_algorithm=None, value=None, json=None):
        super(Signature, self).__init__("signature", json)
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

@Props("Signature", base64="SignedData")
class Signed(CryptVersion):
    def __init__(self, data=None, contentType="text/plain", json=None):
        super(Signed, self).__init__("signed", json)
        if data:
            if not contentType:
                raise CryptoException("Must supply content type with data")
            inner = InnerMessage(data, contentType)
            self.SignedData = JSONdumps(inner)

    def sign(self, key, certs, digest_algorithm="SHA1"):
        val = key.sign(self.SignedData, digest_algorithm)
        self.Signature = Signature(certs, digest_algorithm, key.Algorithm, val)

    def verify(self):
        # TODO: check dates, nonces, etc?
        return self.Signature.verify(self.SignedData)

@Props("Name", "EncryptionAlgorithm", "PkixCertificateHash", base64="EncryptionKey")
class Recipient(CryptBase):
    def __init__(self, cert=None, key=None, json=None):
        super(Recipient, self).__init__("recipient", json)
        if cert:
            self.Name = cert.Name
            self.EncryptionAlgorithm = cert.PublicKey.Algorithm
            self.PkixCertificateHash = cert.hash()
        if key:
            self.EncryptionKey = key

@Props("Algorithm", base64="IV")
class Encryption(CryptBase):
    def __init__(self, algorithm=None, iv=None, json=None):
        super(Encryption, self).__init__("encryption", json)
        if algorithm:
            self.Algorithm = algorithm
        if iv:
            self.IV = iv

@Props("Algorithm", base64="Value")
class Integrity(CryptBase):
    def __init__(self, algorithm=None, value=None, json=None):
        super(Integrity, self).__init__("integrity", json)
        if algorithm:
            self.Algorithm = algorithm
        if value:
            self.Value = value

@Props("ContentType", "Data", date="Date")
class InnerMessage(CryptVersion):
    def __init__(self, data=None, contentType=None, date=None, json=None):
        super(InnerMessage, self).__init__("inner", json)
        if data:
            self.Data = data
        if contentType:
            self.ContentType = contentType
        if date:
            self.Date = date
        elif not json:
            self.Date = get_date()

@Props("Recipients", "Encryption", "Integrity", base64="EncryptedData")
class Encrypted(CryptVersion):
    def __init__(self, data=None, contentType="text/plain", json=None):
        super(Encrypted, self).__init__("encrypted", json)
        if data:
            if not contentType:
                raise CryptoException("Must supply content type with data")
            self.inner = InnerMessage(data, contentType)

    def encrypt(self, toCerts, encryption_algorithm="AES-256-CBC", integrity_algorithm="HMAC-SHA1"):
        (alg, size, mode) = getAlgorithm(encryption_algorithm)
        iv = generateIV(encryption_algorithm)
        self.Encryption = Encryption(encryption_algorithm, iv)

        sk = generateSessionKey(encryption_algorithm)
        mek = kdf(sk, encryption_algorithm)
        js = JSONdumps(self.inner)

        ciphertext = symmetricEncrypt(mek, iv, encryption_algorithm, js)
        self.EncryptedData = ciphertext

        rcpts = []
        if not isinstance(toCerts, (list, tuple)):
            toCerts = (toCerts,)
        for c in toCerts:
            key_exchange = c.PublicKey.encrypt(sk)
            r = Recipient(c, key_exchange)
            rcpts.append(r)
        self.Recipients = rcpts

        mik = kdf(sk, integrity_algorithm)
        mac = hmac(mik, integrity_algorithm, ciphertext)
        self.Integrity = Integrity(integrity_algorithm, mac)
        return (mek, iv)

    def decrypt(self, privKey, name):
        rcpt = None
        for r in self.Recipients:
            if r.Name == name:
                rcpt = r
                break
        if not rcpt:
            raise CryptoException("Name not found")

        ek = rcpt.EncryptionKey
        sk = privKey.decrypt(ek)
        ciphertext = self.EncryptedData
        iv = self.Encryption.IV

        encryption_algorithm = self.Encryption.Algorithm
        mek = kdf(sk, encryption_algorithm)
        plaintext = symmetricDecrypt(mek, iv, encryption_algorithm, ciphertext)
        if (not plaintext) or (len(plaintext) < 20) or (plaintext[0] != '{') or (plaintext[-1] != '}'):
            raise CryptoException("Bad decrypt: " + repr(iv) + ' ' +  repr(plaintext))
        res = JSONloads(plaintext)
        dt = res.Date
        if dt > get_date(): # TODO: clock skew
            raise CryptoException("Message from the future")

        integrity_algorithm = self.Integrity.Algorithm
        mik = kdf(sk, integrity_algorithm)
        mac = hmac(mik, integrity_algorithm, ciphertext)
        if mac != self.Integrity.Value:
            raise CryptoException("Invalid HMAC")

        return res

if __name__ == '__main__':
    priv = PrivateKey(size=512)
    print "priv=" + str(priv)

    pub = priv.PublicKey
    print "pub=" + str(pub)
    cert = pub.genCertificate("joe@example.com", 7)
    print "cert=" + str(cert)
    assert(cert.validate())

    s = Signed("Foo")
    s.sign(priv, cert)
    print "sig=" + str(s)
    assert(s.verify())

    e = Encrypted("BAR")
    e.encrypt(cert)
    print "encrypted=" + str(e)
    d = e.decrypt(priv, "joe@example.com")
    assert(d.Data == "BAR")
