class Certificate(object):
    def __init__(self, encoding, parsed=None):
        self.encoding_ = encoding
        if parsed != None:
            self.username_ = parsed['username']
            self.pubkey_ = parsed['pubkey']

    def getUsername(self):
        return self.username_

    def getBase64(self):
        return self.encoding_

    def getPubkey(self):
        return self.pubkey_



    




    
        




