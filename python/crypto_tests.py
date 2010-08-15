import unittest
import crypto

class TestCrypto(unittest.TestCase):
    keysize = 384
    name = "joe@example.com"

    def setUp(self):
        self.priv = crypto.PrivateKey(size=self.keysize)
        self.cert = self.priv.PublicKey.genCertificate(name=self.name)

    def test_pub_encrypt(self):
        msg = "squeamish_pub"
        pub = self.cert.PublicKey
        ciphertext = pub.encrypt(msg)
        plaintext = self.priv.decrypt(ciphertext)
        self.assertEqual(msg, plaintext)

        msg = "\x00\x00\x00\x00"
        ciphertext = pub.encrypt(msg)
        plaintext = self.priv.decrypt(ciphertext)
        self.assertEqual(msg, plaintext)

        for i in range(128):
            msg = "message: " + str(i)
            ciphertext = pub.encrypt(msg)
            plaintext = self.priv.decrypt(ciphertext)
            self.assertEqual(msg, plaintext)

    def test_sizes(self):
        msg = "squea"
        for i in range(7,10):
            sz = 2**i
            priv = crypto.PrivateKey(size=sz)
            pub = priv.PublicKey
            ciphertext = pub.encrypt(msg)
            plaintext = priv.decrypt(ciphertext)
            self.assertEqual(msg, plaintext)

    def test_PrivKey(self):
        self.assertTrue(self.priv)
        privj = crypto.JSONdumps(self.priv)
        privjl = crypto.JSONloads(privj)
        self.assertTrue(self.priv == privjl)
        self.assertEqual(self.priv.key.d, privjl.key.d)
        self.assertEqual(self.priv.PublicKey.key.n, privjl.PublicKey.key.n)
        self.assertEqual(self.priv.PublicKey.key.e, privjl.PublicKey.key.e)
        
        sig = self.priv.sign("test")
        self.assertTrue(self.priv.PublicKey.verify("test", sig))

        ciphertext = self.priv.PublicKey.encrypt("test")
        plain = self.priv.decrypt(ciphertext)
        self.assertEqual("test", plain)
        self.assertNotEqual(ciphertext, plain)

    def test_PubKey(self):
        pub = self.priv.PublicKey
        self.assertTrue(pub)
        self.assertEqual("RSA-PKCS1-1.5", pub.Algorithm)
        
        pubj = crypto.JSONdumps(pub)
        pubjl = crypto.JSONloads(pubj)
        self.assertTrue(pub == pubjl)
        self.assertEqual(pub.key.n, pubjl.key.n)
        self.assertEqual(pub.key.e, pubjl.key.e)
        self.assertEqual(pub.RsaExponent, pubjl.RsaExponent)
        self.assertEqual(pub.RsaModulus, pubjl.RsaModulus)

    def test_Certificate(self):
        self.assertTrue(self.cert.validate())
        self.assertEqual(self.cert.Name, self.name)
        certj = crypto.JSONdumps(self.cert)
        certjl = crypto.JSONloads(certj)
        self.assertTrue(self.cert == certjl)
        self.assertTrue(certjl.NotBefore == self.cert.NotBefore)

    def test_Signed(self):
        msg = crypto.b64(crypto.generateRandom(1024))
        sig = crypto.Signed(msg)
        sig.sign(self.priv, self.cert)
        inner = crypto.JSONloads(sig.SignedData)
        self.assertEqual(msg, inner.Data)
        self.assertTrue(sig.verify())
        sigj = crypto.JSONdumps(sig)
        sigjl = crypto.JSONloads(sigj)
        self.assertTrue(sig == sigjl)

    def test_Encrypted(self):
        msg = "squeamish"
        e = crypto.Encrypted(msg)
        e.encrypt(self.cert)
        self.assertEqual(self.priv.PublicKey, self.cert.PublicKey)
        plain = e.decrypt(self.priv, self.name)
        self.assertEqual(msg, plain.Data)

        msg = u"\u216B"
        e = crypto.Encrypted(msg)
        e.encrypt(self.cert)
        self.assertEqual(self.priv.PublicKey, self.cert.PublicKey)
        plain = e.decrypt(self.priv, self.name)
        self.assertEqual(msg, plain.Data)

if __name__ == '__main__':
    import sys
    unittest.main(argv=sys.argv)
