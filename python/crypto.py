from crypto_utils import *
import json
import hashlib
import sys

version = "1.0"
JSON_MIME = "application/json"
ca_bundle = []

def set_bundle(b):
    global ca_bundle
    for c in b:
        if c.Type != "certificate":
            raise CryptoException("Invalid bundle")
    ca_bundle = b

def _JSONdefault(o):
    """Turn an object into JSON.  
    Dates and instances of classes derived from CryptoTyped get special handling"""
    if isinstance(o, datetime.datetime):
        return fmt_date(o)
    return o.JSON()

def JSONdumps(o, indent=None):
    "Dump crypto objects to string"
    return json.dumps(o, default=_JSONdefault, indent=indent)

def JSONwrite(o, fp=None, indent=None):
    def wj(p):
        r = json.dump(o, p, default=_JSONdefault, indent=indent)
        if indent:
            p.write("\n")
        return r

    if not fp:
        return wj(sys.stdout)
    elif isinstance(fp, basestring):
        f = open(fp, "w")
        r = wj(f)
        f.close()
        return r
    else:
        return wj(fp)

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
other than plain cause encoding to happen on set, and decoding to
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

@Props("Type")
class CryptoTyped(object):
    """The base class for all crypto objects.  Crypto objects contain
    a dictionary that holds their state in a form easy to be
    translated to JSON.  Getters and setters modify the JSON
    dictionary."""
    def __init__(self, objectType, json=None):
        super(CryptoTyped,self).__init__()
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
    def JSONstr(self):
        return JSONdumps(self.json_)

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

    @classmethod
    def schema(cls):
        "Return the schema for this class"
        pass

@Props("Version")
class CryptoBase(CryptoTyped):
    def __init__(self, objectType, json=None, ver=version):
        super(CryptoBase, self).__init__(objectType, json)
        if json:
            if json.get("Version", None) != ver:
                raise CryptoException("Invalid version")
        elif objectType:
            self.json_["Version"] = ver

    def __cmp__(self, other):
        r = super(CryptoBase, self).__cmp__(other)
        if r:
            return r
        r = cmp(self.Version, other.Version)
        if r:
            return r

        return 0

    def write(self, fp=None, indent=None):
        JSONwrite(self, fp, indent)

    @classmethod
    def read(cls, fp):
        """Read all data from the given file name or file-like object pointer.  
Closes the file handle when complete."""
        def rj(p):
            data = json.load(p, object_hook=_JSONobj)
            p.close()
            return data

        if isinstance(fp, basestring):
            f = open(fp, "r")
            return rj(f)
        else:
            return rj(fp)

    def wrapSign(self, ca_priv, ca_cert):
        s = Signed(self.JSONstr, JSON_MIME)
        s.sign(ca_priv, ca_cert)
        return s

    def wrapEncrypt(self, key):
        e = Encrypted(self.JSONstr, JSON_MIME)
        e.encrypt(key=key)
        return e

@Props("Name", "PublicKey", "Hash", "Serial", date=("NotBefore", "NotAfter"))
class Certificate(CryptoBase):
    def __init__(self, name=None, pubkey=None, serial=None, validityDays=None, json=None):
        super(Certificate, self).__init__("certificate", json)

        if name:
            self.Name = name
        if pubkey:
            self.PublicKey = pubkey
        if validityDays:
            self.NotBefore = get_date()
            self.NotAfter = get_date(validityDays)
        if serial is not None:
            self.Serial = serial
        if "Serial" not in self.json_:
            self.Serial = 0
        if "Hash" not in self.json_:
            self.Hash = self.hash()
        else:
            if self.Hash != self.hash():
                raise CryptoException("Invalid certificate hash")

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
        pk = self.PublicKey
        source = self.Name + self.json_["NotAfter"] + self.json_["NotBefore"] + pk.Algorithm
        source = source.encode('utf8') + long_to_bytes(pk.RsaExponent) + long_to_bytes(pk.RsaModulus)
        return b64(hashlib.sha1(source).digest())

    def readable_hash(self):
        dig = b64d(self.Hash).encode('hex')
        f = []
        for i in range(len(dig) / 2):
            f.append(dig[i*2:(i+1)*2])
        return ":".join(f)
        
@Props("Algorithm", long=("RsaExponent", "RsaModulus"))
class PublicKey(CryptoTyped):
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
class PrivateKey(CryptoBase):
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

def check_ca(signed):
    "Check if this block was signed by a trusted CA"
    global ca_bundle
    if not ca_bundle:
        sys.stderr.write("WARNING: no CA checks!\n")
        return True
    cert = signed.Signature.Certificate
    for c in ca_bundle:
        if cert == c:
            return c.validate()
    return False

def check_cert(cert, trusted=False):
    if not cert:
        raise CryptoException("Certificate required")
    incert = cert
    while incert.Type == "signed":
        if not trusted:
            trusted = check_ca(incert)
        if not incert.verify(trusted):
            raise CryptoException("Invalid signature")
        incert = incert.getInnerJSON()

    if not trusted:
        raise CryptoException("Not signed by a trusted CA")
    if incert.Type != "certificate":
        raise CryptoException("Not a certificate")
    if not incert.validate():
        raise CryptoException("Invalid certificate")
    return incert

@Props("Certificate", "Signer", "DigestAlgorithm", "SignatureAlgorithm", long="Value")
class Signature(CryptoTyped):
    def __init__(self, cert=None, signer=None, digest_algorithm=None, sig_algorithm=None, value=None, json=None):
        super(Signature, self).__init__("signature", json)
        if cert:
            self.Certificate = cert
        if signer:
            self.Signer = signer
        if digest_algorithm:
            self.DigestAlgorithm = digest_algorithm
        if sig_algorithm:
            self.SignatureAlgorithm = sig_algorithm
        if value:
            self.Value = value

    def verify(self, data, trust_certs):
        cert = check_cert(self.Certificate, trust_certs)

        if cert.Name != self.Signer:
            return False

        return cert.PublicKey.verify(data, self.Value, self.SignatureAlgorithm, self.DigestAlgorithm)

@Props("Signature", base64="SignedData")
class Signed(CryptoBase):
    def __init__(self, data=None, contentType="text/plain", name=None, json=None):
        super(Signed, self).__init__("signed", json)
        if data:
            if not contentType:
                raise CryptoException("Must supply content type with data")
            inner = InnerMessage(data, contentType, name=name)
            self.SignedData = JSONdumps(inner)

    def sign(self, key, cert, digest_algorithm="SHA1"):
        val = key.sign(self.SignedData, digest_algorithm)
        incert = check_cert(cert, True)

        if incert.PublicKey != key.PublicKey:
            raise CryptoException("Cert doesn't match key")

        self.Signature = Signature(cert, incert.Name, digest_algorithm, key.Algorithm, val)

    def verify(self, trust_certs=False):
        # TODO: check dates, nonces, etc?
        return self.Signature.verify(self.SignedData, trust_certs)

    def getInnerJSON(self):
        inner = JSONloads(self.SignedData)
        if inner.ContentType != JSON_MIME:
            raise CryptoException("Invalid data type, '%s' != '%s'" % (inner.ContentType, JSON_MIME))
        js = JSONloads(inner.Data)
        return js

@Props("Name", "EncryptionAlgorithm", "CertificateHash", base64="EncryptionKey")
class Recipient(CryptoTyped):
    def __init__(self, cert=None, key=None, json=None):
        super(Recipient, self).__init__("recipient", json)
        if cert:
            self.EncryptionAlgorithm = cert.PublicKey.Algorithm
            self.CertificateHash = cert.Hash
            self.Name = cert.Name
        if key:
            self.EncryptionKey = key

@Props("Algorithm", base64="IV")
class Encryption(CryptoTyped):
    def __init__(self, algorithm=None, iv=None, json=None):
        super(Encryption, self).__init__("encryption", json)
        if algorithm:
            self.Algorithm = algorithm
        if iv:
            self.IV = iv

@Props("Algorithm", base64="Value")
class Integrity(CryptoTyped):
    def __init__(self, algorithm=None, value=None, json=None):
        super(Integrity, self).__init__("integrity", json)
        if algorithm:
            self.Algorithm = algorithm
        if value:
            self.Value = value

@Props("ContentType", "Data", "Name", date="Date")
class InnerMessage(CryptoBase):
    def __init__(self, data=None, contentType=None, date=None, name=None, json=None):
        super(InnerMessage, self).__init__("inner", json)
        if data:
            self.Data = data
        if contentType:
            self.ContentType = contentType
        if name:
            self.Name = name
        if date:
            self.Date = date
        elif not json:
            self.Date = get_date()

@Props("Recipients", "Encryption", "Integrity", base64="EncryptedData")
class Encrypted(CryptoBase):
    def __init__(self, data=None, contentType="text/plain", name=None, json=None):
        super(Encrypted, self).__init__("encrypted", json)
        if data:
            if not contentType:
                raise CryptoException("Must supply content type with data")
            self.inner = InnerMessage(data, contentType, name=name)

    def encrypt(self, toCerts=None, encryption_algorithm="AES-256-CBC", integrity_algorithm="HMAC-SHA1", key=None):
        (alg, size, mode) = getAlgorithm(encryption_algorithm)
        iv = generateIV(encryption_algorithm)
        self.Encryption = Encryption(encryption_algorithm, iv)

        if key:
            sk = key
        else:
            sk = generateSessionKey(encryption_algorithm)
        mek = kdf(sk, encryption_algorithm)
        js = JSONdumps(self.inner)

        ciphertext = symmetricEncrypt(mek, iv, encryption_algorithm, js)
        self.EncryptedData = ciphertext

        if toCerts:
            rcpts = []
            if not isinstance(toCerts, (list, tuple)):
                toCerts = (toCerts,)
            for c in toCerts:
                b = check_cert(c, True)
                key_exchange = b.PublicKey.encrypt(sk)
                r = Recipient(b, key_exchange)
                rcpts.append(r)
            self.Recipients = rcpts

        mik = kdf(sk, integrity_algorithm)
        mac = hmac(mik, integrity_algorithm, ciphertext)
        self.Integrity = Integrity(integrity_algorithm, mac)

    def symmetricDecrypt(self, key):
        ciphertext = self.EncryptedData
        iv = self.Encryption.IV

        encryption_algorithm = self.Encryption.Algorithm
        mek = kdf(key, encryption_algorithm)
        plaintext = symmetricDecrypt(mek, iv, encryption_algorithm, ciphertext)
        if (not plaintext) or (len(plaintext) < 67) or (plaintext[0] != '{') or (plaintext[-1] != '}'):
            raise CryptoException("Bad decrypt: " + repr(iv) + ' ' +  repr(plaintext))
        res = JSONloads(plaintext)
        dt = res.Date
        if dt > get_date(): # TODO: clock skew
            raise CryptoException("Message from the future")

        integrity_algorithm = self.Integrity.Algorithm
        mik = kdf(key, integrity_algorithm)
        mac = hmac(mik, integrity_algorithm, ciphertext)
        if mac != self.Integrity.Value:
            raise CryptoException("Invalid HMAC")
        return res

    def decrypt(self, privKey, cert=None, name=None, trusted=False):
        rcpt = []
        if cert:
            cert = check_cert(cert, trusted)
            h = cert.Hash
            rcpt += [r for r in self.Recipients if r.CertificateHash == h]
        if name:
            rcpt += [r for r in self.Recipients if r.Name == name]

        if not rcpt:
            raise CryptoException("Name/certificate not found in recipients")
        if len(rcpt) > 1:
            raise CryptoException("Too many matches found in recipients")
        rcpt = rcpt[0]

        ek = rcpt.EncryptionKey
        sk = privKey.decrypt(ek)
        res = self.symmetricDecrypt(sk)

        return res

    def decryptJSON(self, key):
        res = self.symmetricDecrypt(key)
        if res.ContentType != JSON_MIME:
            raise CryptoException("Invalid data type, not '%s'" % JSON_MIME)
        js = JSONloads(res.Data)
        return js
