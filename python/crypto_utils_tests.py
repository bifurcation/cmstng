import unittest
from crypto_utils import *

class TestCryptoUtils(unittest.TestCase):
    keysize = 384
    name = "joe@example.com"

    def test_xors(self):
        self.assertRaises(AssertionError, xors)
        self.assertRaises(AssertionError, xors, "")
        self.assertEqual("", xors("", ""))
        self.assertEqual("", xors("", "", ""))
        self.assertEqual("", xors("", "", ""))
        self.assertEqual("\x01", xors("\x00", "\x01"))
        self.assertEqual("\x00", xors("\x00", "\x01", "\x01"))
        self.assertEqual("\x00\x01\x00", xors("\x00\x00\x00", "\x01\x00\x01", "\x01\x01\x01"))
        
    def test_pad(self):
        msg = ""
        for i in range(65):
            p = pad(msg, 16)
            self.assertEqual(0, len(p) % 16)
            u = unpad(p)
            self.assertEqual(msg, u)
            msg += chr(32 + i)

    def test_pad_1_5(self):
        msg = "foo"
        pad = pad_1_5(msg, 16)
        self.assertTrue(pad[0:2] == "\x00\x02")
        unpad = unpad_1_5(pad)
        self.assertEquals(msg, unpad)
        unpad = unpad_1_5(pad[1:])
        self.assertEquals(msg, unpad)
        msg = "\x00\x00\x00\x00"
        pad = pad_1_5(msg, 16)
        self.assertTrue(pad[0:2] == "\x00\x02")
        unpad = unpad_1_5(pad)
        self.assertEquals(msg, unpad)
        unpad = unpad_1_5(pad[1:])
        self.assertEquals(msg, unpad)

    def test_pad_oaep(self):
        msg = "foo"
        k = 48
        pad = pad_oaep_sha1(msg, k)
        self.assertTrue(pad[0] == "\x00")
        unpad = unpad_oaep_sha1(pad, k)
        self.assertEquals(msg, unpad)
        msg = "\x00\x00\x00\x00"
        pad = pad_oaep_sha1(msg, k)
        unpad = unpad_oaep_sha1(pad, k)
        self.assertEquals(msg, unpad)

    def test_P_SHA256(self):
        a = P_SHA256("secret", "AES-256-CBC", 40)
        self.assertEquals(40, len(a))

    def test_alg(self):
        (alg, size, mode) = getAlgorithm("AES-256-CBC")
        self.assertEqual(alg.__name__, "Crypto.Cipher.AES")
        self.assertEqual(size, 32)
        self.assertEqual(mode, Crypto.Cipher.AES.MODE_CBC)

        (alg, size, mode) = getAlgorithm("AES-128-CBC")
        self.assertEqual(alg.__name__, "Crypto.Cipher.AES")
        self.assertEqual(size, 16)
        self.assertEqual(mode, Crypto.Cipher.AES.MODE_CBC)        

    def test_iv(self):
        alg = "AES-256-CBC"
        iv = generateIV(alg)
        self.assertEqual(len(iv), 16)

    def test_key(self):
        alg = "AES-256-CBC"
        key = generateSessionKey(alg)
        self.assertEqual(len(key), 32)
        mek = kdf(key, alg,PBKDF2_HMAC_SHA1_1024)
        self.assertEqual(len(mek), 32)

    def test_sym_encrypt(self):
        msg = "squeamish_sym"
        key = "12345678901234561234567890123456"
        iv = "1234567890123456"
        alg = "AES-256-CBC"
        ciphertext = symmetricEncrypt(key, iv, alg, msg)
        plaintext = symmetricDecrypt(key, iv, alg, ciphertext)
        self.assertEqual(msg, plaintext)

    def test_hmac(self):
        msg = "squeamish"
        mac = hmac("foo", "HMAC-SHA256", msg)
        machex = mac.encode('hex')
        self.assertEqual("2b430ac3c06c6a9b673c223c748a952417c4cabecdca88993850537f56a213b4", machex)

    def test_PBKDF(self):
        # test vectors from draft-josefsson-pbkdf2-test-vectors-02
        tests = [
            ["password", "salt", 1, 20, 
             "0c60c80f961f0e71f3a9b524af6012062fe037a6"],
            ["password", "salt", 2, 20, 
             "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"],
            ["password", "salt", 4096, 20, 
             "4b007901b765489abead49d926f721d065a429c1"],
            # takes about 10mins to run on my MacBookPro.
#            ["password", "salt", 16777216, 20,
#             "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"],
            ["passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
             "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"],
            ["pass\x00word", "sa\x00lt", 4096, 16,
             "56fa6aa75548099dcc37d7f03425e0c3"],
            ]
        i=0
        for (pw, salt, c, dk, expected) in tests:
            k = PBKDF2_HMAC_SHA1(pw, salt, c, dk)
            self.assertEqual(expected.decode('hex'), k)
            i += 1

    def test_AES_XCBC_MAC(self):
        # test vectors from RFC 3566, section 4.6
        vectors = [
            ["000102030405060708090a0b0c0d0e0f", "", "75f0251d528ac01c4573dfd584d79f29"],
            ["000102030405060708090a0b0c0d0e0f", "000102", "5b376580ae2f19afe7219ceef172756f"],
            ["000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f", "d2a246fa349b68a79998a4394ff7a263"],
            ["000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f10111213", "47f51b4564966215b8985c63055ed308"],
            ["000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "f54f0ec8d2b9f3d36807734bd5283fd4"],
            ["000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021", "becbb3bccdb518a30677d5481fb6b4d8"],
            ["000102030405060708090a0b0c0d0e0f", "00" * 1000, "f0dafee895db30253761103b5d84528f"]
        ]
        for (K, M, expected) in vectors:
            self.assertEqual(expected.decode('hex'), AES_XCBC_MAC(K.decode('hex'), M.decode('hex')))

if __name__ == '__main__':
    import sys
    unittest.main(argv=sys.argv)
