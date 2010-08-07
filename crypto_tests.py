import unittest
import crypto
import Crypto

class TestCertificate(unittest.TestCase):
    def setUp(self):
        self.pair = crypto.KeyPair("joe", 256)
        self.priv = self.pair.Privkey
        self.cert = self.pair.Certificate

    def test_cert(self):
        self.assertTrue(self.cert.validate())

    def test_pad(self):
        msg = ""
        for i in range(65):
            pad = crypto.pad(msg, 16)
            self.assertEqual(0, len(pad) % 16)
            unpad = crypto.unpad(pad)
            self.assertEqual(msg, unpad)
            msg += chr(32 + i)

    def test_alg(self):
        (alg, size, mode) = crypto.getCipherAlgorithm("AES-256-CBC")
        self.assertEqual(alg.__name__, "Crypto.Cipher.AES")
        self.assertEqual(size, 256)
        self.assertEqual(mode, Crypto.Cipher.AES.MODE_CBC)        

    def test_pub_encrypt(self):
        msg = "squeamish"
        pub = self.cert.PublicKey
        ciphertext = pub.encrypt(msg)
        plaintext = self.priv.decrypt(ciphertext)
        self.assertEqual(msg, plaintext)
    
    def test_iv(self):
        alg = "AES-256-CBC"
        iv = crypto.generateIV(alg)
        self.assertEqual(len(iv), 16)

    def test_key(self):
        alg = "AES-256-CBC"
        key = crypto.generateSessionKey(alg)
        self.assertEqual(len(key), 32 - len(alg) - 1)
        mek = crypto.kdf(key, alg)
        self.assertEqual(len(mek), 32)

    def test_sym_encrypt(self):
        msg = "squeamish"
        key = "12345678901234561234567890123456"
        iv = "1234567890123456"
        alg = "AES-256-CBC"
        ciphertext = crypto.symmetricEncrypt(key, iv, alg, msg)
        plaintext = crypto.symmetricDecrypt(key, iv, alg, ciphertext)
        self.assertEqual(msg, plaintext)

    def test_hmac(self):
        msg = "squeamish"
        mac = crypto.hmac("foo", "HMAC-SHA256", msg)
        machex = mac.encode('hex')
        self.assertEqual("2b430ac3c06c6a9b673c223c748a952417c4cabecdca88993850537f56a213b4", machex)


if __name__ == '__main__':
    unittest.main()
