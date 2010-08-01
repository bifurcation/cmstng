import json

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

    def verify(self, signature, signature_algorithm, digest_algorithm, signed_data):
        return True

    def encrypt(self, plaintext):
        return "Encrypted key"

    def getBase64(self):
        return self.encoding_.encode("base64")

class PrivateKey(object):
    def __init__(self, encoding):
        self.encoding_ = encoding

    def sign(self, digest_algorithm, signed_data):
        return "Signature" + "+" + digest_algorithm

    def decrypt(self, ciphertext):
        return "Decrypted"

    def getAlgorithm(self):
        return "RSA-PKCS1-1.5"
    
    

    




    
        




