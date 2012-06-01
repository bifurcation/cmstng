# Python module to support JOSE
#
# At this point, things are very rough, with some basic
# functions to create/validate/encrypt/decrpt the basic
# objects with fixed algorithms.  
#
# Initial thoughts on a nicer API are in the commented-
# out section at the bottom.
#
# Dependencies:
# -- PyCrypto: https://www.dlitz.net/software/pycrypto/


import json
import base64
import struct
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_sig
from Crypto.Hash import SHA, SHA256, HMAC
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher.AES import AESCipher
from Crypto.Util.strxor import strxor
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher


def jose_enc(x):
    return base64.urlsafe_b64encode(x)
def jose_dec(x):
    return base64.urlsafe_b64decode(str(x))


def jose_signed_sign(key, content):
    h = SHA.new(content)
    signer = PKCS1_sig.new(key)
    sig = signer.sign(h)

    jose = {
        "v": 1,
        "t": "s",
        "c": jose_enc(content),
        "da": "sha1",
        "sa": "pkcs1",
        "s": jose_enc(sig),
        "p": ["rsa", key.n, key.e]
    }
    return json.dumps(jose, separators=(',',':'))

def jose_signed_verify(josestr):
    jose = json.loads(josestr)
    if len(jose) < 3:
        raise ("Signed object too short",)
    elif jose["t"] != "s":
        raise ("JOSE object is not a signed object",)
    
    content = jose_dec(jose["c"])
    # Pull the key
    if jose["p"][0] != "rsa":
        raise ("Only RSA keys supported")
    key = RSA.construct( (long(jose["p"][1]), long(jose["p"][2])) )
    
    # Check the signature type
    if jose["da"] != "sha1":
        raise ("Only sha1 hashing supported",)
    if jose["sa"] != "pkcs1":
        raise ("Only PKCS#1 signature supported",)
    
    sig = jose_dec(jose["s"])
    h = SHA.new(content)
    verifier = PKCS1_sig.new(key)
    return verifier.verify(h, sig)

# NB: Wrapped object must be a multiple of 8 bytes long
# http://tools.ietf.org/html/rfc3394#section-2.2.1
def aes_key_wrap(key, p):
    assert( len(p) % 8 == 0 )
    
    n = len(p)/8
    r = range(n+1)
    r[0] = b'\0\0\0\0\0\0\0\0'
    for i in range(1,n+1):
        r[i] = p[(i-1)*8:i*8]
    a = b'\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6'

    aes = AESCipher(key)
    for j in range(0,6):
        for i in range(1,n+1):
            t = struct.pack("!q", (n*j)+i)
            b = aes.encrypt(a+r[i])     # B = AES(K, A | R[i])
            a = strxor(b[:8], t)        # A = MSB(64, B) ^ t where t = (n*j)+i
            r[i] = b[8:]                # R[i] = LSB(64, B)

    r[0] = a
    return "".join(r)

# NB: Wrapped object must be a multiple of 8 bytes long
# http://tools.ietf.org/html/rfc3394#section-2.2.2
def aes_key_unwrap(key, c):
    assert( len(c) % 8 == 0 )
    
    n = len(c)/8 - 1
    r = range(n+1)
    r[0] = b'\0\0\0\0\0\0\0\0'
    for i in range(1,n+1):
        r[i] = c[i*8:(i+1)*8]
    a = c[:8]

    aes = AESCipher(key)
    for j in range(5,-1,-1):
        for i in range(n,0,-1):
            t = struct.pack("!q", (n*j)+i)
            a = strxor(a, t)
            b = aes.decrypt(a+r[i])     # B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
            a = b[:8]                   # A = MSB(64, B)
            r[i] = b[8:]                # R[i] = LSB(64, B)

    if (a == b'\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6'):
        return "".join(r[1:])
    else:
        raise "Key unwrap integrity check failed"


def jose_mac_encode(key, keytag, content):
    cmk = Random.get_random_bytes(32)   # Master key
    wcmk = aes_key_wrap(key, cmk)        # Wrapped master key
    print "MAC master key: "+ cmk.encode("hex")

    hmac = HMAC.new(cmk, digestmod=SHA)
    hmac.update(content)
    mac = hmac.digest()

    jose = {
        "v": 1,
        "t": "a",
        "c": jose_enc(content),
        "a": "hmac-sha1",
        "m": jose_enc(mac),
        "k": [{
            "t": "s",
            "a": "aes",
            "k": jose_enc(wcmk),
            "i": jose_enc(keytag)
        }]
    }
    return json.dumps(jose, separators=(',',':'))

def jose_mac_verify(key, keytag, josestr):
    jose = json.loads(josestr)
    if len(jose) < 5:
        raise ("Authenticated object too short",)
    elif jose["t"] != "a":
        raise ("JOSE object is not an authenticated object",)
    
    content = jose_dec(jose["c"])
    jmac = jose_dec(jose["m"])
    # Pull 
    if jose["a"] != "hmac-sha1":
        raise ("Only HMAC-SHA1 supported")
    
    # Check the key encipherment type and key tag
    if jose["k"][0]["t"] != "s":
        raise ("Only key transport supported",)
    if jose["k"][0]["a"] != "aes":
        raise ("Only AES key wrapping supported",)
    jtag = jose_dec(jose["k"][0]["i"])
    if jtag != keytag:
        raise ("Unknown key",)
    
    wcmk = jose_dec(jose["k"][0]["k"])
    cmk = aes_key_unwrap(key, wcmk)
    
    hmac = HMAC.new(cmk, digestmod=SHA)
    hmac.update(content)
    mac = hmac.digest()

    return (mac == jmac)

# Uses PKCS#1 
def rsa_key_wrap(key, p):
    cipher = PKCS1_cipher.new(key)
    return cipher.encrypt(p)
def rsa_key_unwrap(key, c):
    sentinel = Random.get_random_bytes(48)
    cipher = PKCS1_cipher.new(key)
    return cipher.decrypt(c, sentinel)

def jose_enc_encrypt(key, content):
    ke = Random.get_random_bytes(16)    # Encryption key
    ka = Random.get_random_bytes(32)    # Authentication key
    cmk = ke + ka                       # Master key
    wcmk = rsa_key_wrap(key, cmk)       # Wrapped master key
    print "Encryption master key: "+ cmk.encode("hex")

    # Pad the content out to block length
    x = AES.block_size - (len(content) % AES.block_size)
    if x == 0:
        x = AES.block_size
    econtent = content + (struct.pack("B",x) * x)

    # Compute the encrypted body
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(ke, AES.MODE_CBC, iv)
    S = cipher.encrypt(econtent)

    # Compute MAC with no associated data A
    hmac = HMAC.new(ka, digestmod=SHA)
    n = Random.get_random_bytes(16) # Nonce
    ln = struct.pack("!q", len(n))
    la = struct.pack("!q", 0)
    print (n+econtent+ln+la).encode("hex")
    hmac.update(n + S + ln + la)
    T = hmac.digest()

    # Combine encrypted body with MAC
    econtent = S + T

    jose = {
        "v": 1,
        "t": "e",
        "c": jose_enc(econtent),
        "ea": ["aead-gen","aes128-cbc","hmac-sha1", {
            "n": jose_enc(n),
            "iv": jose_enc(iv)
        }],
        "k": [{
            "t":"p",
            "a":"pkcs1",
            "k": jose_enc(wcmk),
            "p":["rsa", key.n, key.e]
        }]
    }
    return json.dumps(jose, separators=(',',':'))

def jose_enc_decrypt(key, josestr):
    jose = json.loads(josestr)
    # TODO Check public key, algorithms
    
    # Unwrap wrapped key
    wcmk = jose_dec(jose["k"][0]["k"])
    cmk = rsa_key_unwrap(key, wcmk)
    ke = cmk[:16]
    ka = cmk[16:]

    # Split the encrypted content
    econtent = jose_dec(jose["c"]);
    S = econtent[:-SHA.digest_size]
    T = econtent[-SHA.digest_size:]

    # Verify the MAC (no associated data)
    n = jose_dec(jose["ea"][3]["n"])
    hmac = HMAC.new(ka, digestmod=SHA)
    ln = struct.pack("!q", len(n))
    la = struct.pack("!q", 0)
    print (n+S+ln+la).encode("hex")
    hmac.update(n + S + ln + la)
    Tp = hmac.digest()
    if Tp != T:
        print T
        raise ("Integrity check failed")

    # Decrypt the contents 
    iv = jose_dec(jose["ea"][3]["iv"])
    cipher = AES.new(ke, AES.MODE_CBC, iv)
    econtent = cipher.decrypt(S)

    # Trim the padding
    lp = struct.unpack("B", econtent[-1])[0]
    econtent = econtent[:-lp]

    return econtent




# Random 1024-bit key pair
n=122378242636949767096510314082242225552919910128104821779203578694182897715692697180786327843327209974588179729985336687220073096675483822073402642772681280616976104546172553294754270183035629160096644487460472226901463659298295134941056728958332815261388392162051040350819406566563967272795487285560945461681L
e=65537L
d=75878357104421224437595505023603656489355639532714946259333466900195645950793792055499220774731848838326299393136001896412525295381361446357824074783220210510789365416579392505080998449581120603587386341503989723156683831337820073532167127371647559445356352608366797697088725562143293140567116070641632520193L
rsakey = RSA.construct( (n,e,d) )

# Random 128-bit symmetric key
symmkey = "4A5055F46000455098EFBF40EF23752B".decode("hex")
keytag  = SHA.new(symmkey).digest()

content = "Attack at dawn!"


joses = jose_signed_sign(rsakey, content)
josesv = jose_signed_verify(joses)
josea = jose_mac_encode(symmkey, keytag, content)
joseav = jose_mac_verify(symmkey, keytag, josea)
josee = jose_enc_encrypt(rsakey, content)
joseed = jose_enc_decrypt(rsakey, josee)

# Test success
if josesv:
    print "Signature worked"
else:
    print "Signature failed"
if joseav:
    print "Authentication worked"
else:
    print "Authentication failed"
if joseed == content:
    print "Encryption worked: "+content
else:
    print "Encryption failed"


print joses
print josea
print josee


quit()



##### FULL FANCY LIBRARY FOLLOWS #####
#
## JSMS
## Utility class that holds constants and handy functions
#class JSMS:
#    SignedData = "s"
#    AuthenticatedData = "a"
#    EncryptedData = "e"
#
#    def b64encode(x):
#        return base64.urlsafe_b64encode(x)
#    def b64decode(x):
#        return base64.urlsafe_b64decode(str(x))
#
## JSMSObject
## Parent class for JSMS objects
## NB: Convention to describe field names with underscores
#class JSMSObject:
#    _version = "v"
#    _type = "t"
#    _content = "c"
#    
#    def __init__(self, content=None):
#        self.d = {}
#        self.d[JSMS._version] = 1
#        if content:
#            self.setContent(content)
#
#    def getContent(self):
#        return JSMS.b64decode(self.d[JSMSObject._content])
#    
#    def setContent(self, content):
#        self.d[JSMSObject._content] = JSMS.b64encode(content)
#
#    def fromJSON(json):
#        obj = JSMSObject();
#        obj.loadJSON(json)
#        return obj
#
#    def loadJSON(self,json):
#        self.d = json.loads(json)
#        # TODO Validate that it's actually JSMS-formatted
#
#    def toJSON(self):
#        return json.dumps(self.d, separators=(',',':'))
#
#
#class JSMSSignedData(JSMSObject):
#    def __init__(self, content=None):
#        JSMSObject.__init__(self,content)
#        self.d[JSMSObject._type] = JSMS.SignedData
#
#    # Apply signature to this object
#    # key : A PublicKey object representing a key directly
#    # Returns nothing, simply modifies internal state
#    def sign(self, key):
#        # TODO Implement
#        pass
#
#    # Verify this object using internal key info
#    # Returns boolean indicating success of validation
#    # XXX: Also return TA info?
#    def verify(self):
#        # TODO Implement
#        pass
#
#    # XXX: Implement further methods to access key info?
#
#
#class JSMSAuthenticatedData(JSMSObject):
#    def __init__(self, content=None):
#        JSMSObject.__init__(self,content)
#        self.d[JSMSObject._type] = JSMS.AuthenticatedData
#
#    # Apply a MAC to this object, using a key encryption key
#    # key : A raw key to be used as the KEK
#    # tag : The tag to be presented for the key
#    # mac_algo : AlgorithmIdentifier for the MAC algorithm
#    # enc_algo : AlgorithmIdentifier for the encryption algorithm
#    def apply_mac_kek(self, key, tag, mac_algo, enc_algo):
#        # TODO Implement
#        pass
#
#    # Apply a MAC to this object, using key transport 
#    # key : A PublicKey object to be used to wrap the key
#    # mac_algo : AlgorithmIdentifier for the MAC algorithm
#    # enc_algo : AlgorithmIdentifier for the encryption algorithm
#    def apply_mac_ktr(self, key, mac_algo, enc_algo):
#        # TODO Implement
#        pass
#
#    # Apply a MAC to this object, using key agreement
#    # key : A PublicKey object to be used to wrap the key
#    # mac_algo : AlgorithmIdentifier for the MAC algorithm
#    # enc_algo : AlgorithmIdentifier for the encryption algorithm
#    def apply_mac_ktr(self, okey, rkey, ukm, mac_algo, enc_algo):
#        # TODO Implement
#        pass
#
#    # keylib : A dictionary of (tag,key) mappings
#    # Returns boolean
#    # XXX: Also return info about which key was used?
#    def verify_mac(self, keylib):
#        pass
#
#
#class JSMSEncryptedData(JSMSObject):
#    def __init__(self, content=None):
#        JSMSObject.__init__(self,content)
#        self.d[JSMSObject._type] = JSMS.AuthenticatedData
#
#    # Apply a MAC to this object, using a key encryption key
#    # key : A raw key to be used as the KEK
#    # tag : The tag to be presented for the key
#    # mac_algo : AlgorithmIdentifier for the MAC algorithm
#    # enc_algo : AlgorithmIdentifier for the encryption algorithm
#    def apply_mac_kek(self, key, tag, mac_algo, enc_algo):
#        # TODO Implement
#        pass
#
#    # Apply a MAC to this object, using key transport 
#    # key : A PublicKey object to be used to wrap the key
#    # mac_algo : AlgorithmIdentifier for the MAC algorithm
#    # enc_algo : AlgorithmIdentifier for the encryption algorithm
#    def apply_mac_ktr(self, key, mac_algo, enc_algo):
#        # TODO Implement
#        pass
#
#    # Apply a MAC to this object, using key agreement
#    # key : A PublicKey object to be used to wrap the key
#    # mac_algo : AlgorithmIdentifier for the MAC algorithm
#    # enc_algo : AlgorithmIdentifier for the encryption algorithm
#    def apply_mac_ktr(self, okey, rkey, ukm, mac_algo, enc_algo):
#        # TODO Implement
#        pass
#
#    # keylib : A dictionary of (tag,key) mappings
#    # Returns boolean
#    # XXX: Also return info about which key was used?
#    def verify_mac(self, keylib):
#        pass
