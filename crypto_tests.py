import unittest
import crypto
import Crypto

class TestCertificate(unittest.TestCase):
    keysize = 256
    name = "joe@example.com"

    def setUp(self):
        self.pair = crypto.KeyPair(self.name, self.keysize)
        self.priv = self.pair.Privkey
        self.cert = self.pair.Certificate

    def test_pair(self):
        self.assertEqual(self.pair.priv.size(), self.keysize-1)
        self.assertEqual(self.pair.name, self.name)

    def test_cert(self):
        self.assertTrue(self.cert.validate())
        self.assertEqual(self.cert.Name, self.name)

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

    def test_PBKDF(self):
        # test vectors from draft-josefsson-pbkdf2-test-vectors-02
        tests = [
            ["password", "salt", 1, 20, 
             "0c60c80f961f0e71f3a9b524af6012062fe037a6".decode('hex')],
            ["password", "salt", 2, 20, 
             "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957".decode('hex')],
            ["password", "salt", 4096, 20, 
             "4b007901b765489abead49d926f721d065a429c1".decode('hex')],
            # takes about 10mins to run on my MacBookPro.
#            ["password", "salt", 16777216, 20,
#             "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984".decode('hex')],
            ["passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
             "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038".decode('hex')],
            ["pass\x00word", "sa\x00lt", 4096, 16,
             "56fa6aa75548099dcc37d7f03425e0c3".decode('hex')],
            ]
        i=0
        for (pw, salt, c, dk, expected) in tests:
            k = crypto.PBKDF2_HMAC_SHA1(pw, salt, c, dk)
            self.assertEqual(expected, k)
            i += 1


if __name__ == '__main__':
    unittest.main()
