priv={
  "PublicKey": {
    "RsaExponent": "AQAB", 
    "Type": "publickey", 
    "Algorithm": "RSA-PKCS1-1.5", 
    "RsaModulus": "i0t9JRoa8atoEJUF73B3zqQsBmKBpq2vuL8M2eGRx46D8GkQavjwtLuaZccTy7JiwI8Z9AWOzJoTO2Du+0lLTQ=="
  }, 
  "Version": "1.0", 
  "Type": "privatekey", 
  "Algorithm": "RSA-PKCS1-1.5", 
  "PrivateExponent": "Dyz2QWiKrvGhsMzLjL6QDu9L7JYm0eXyUwpdeA9fNoJh0/7s0f1/Z/zb7rRj+XkFx0zn+KnBMg3vtcVQVz0pcQ=="
}
pub={
  "RsaExponent": "AQAB", 
  "Type": "publickey", 
  "Algorithm": "RSA-PKCS1-1.5", 
  "RsaModulus": "i0t9JRoa8atoEJUF73B3zqQsBmKBpq2vuL8M2eGRx46D8GkQavjwtLuaZccTy7JiwI8Z9AWOzJoTO2Du+0lLTQ=="
}
cert={
  "Name": "joe@example.com", 
  "NotBefore": "2010-08-12T17:13:34Z", 
  "NotAfter": "2010-08-19T17:13:34Z", 
  "PublicKey": {
    "RsaExponent": "AQAB", 
    "Type": "publickey", 
    "Algorithm": "RSA-PKCS1-1.5", 
    "RsaModulus": "i0t9JRoa8atoEJUF73B3zqQsBmKBpq2vuL8M2eGRx46D8GkQavjwtLuaZccTy7JiwI8Z9AWOzJoTO2Du+0lLTQ=="
  }, 
  "Version": "1.0", 
  "Type": "certificate"
}
sig={
  "SignedData": "eyJEYXRlIjogIjIwMTAtMDgtMTJUMTc6MTM6MzRaIiwgIkRhdGEiOiAiRm9vIiwgIlZlcnNpb24iOiAiMS4wIiwgIlR5cGUiOiAiaW5uZXIiLCAiQ29udGVudFR5cGUiOiAidGV4dC9wbGFpbiJ9", 
  "Version": "1.0", 
  "Type": "signed", 
  "Signature": {
    "DigestAlgorithm": "SHA1", 
    "Value": "ac1eQ0HbILuRyKvZ2CedvYmeDP8vYX73DqLxt+BYE09nPYLK/T1Lzuf+yIS1MZfzp3+y2Vx3jAQ4ytkX9QUX6Q==", 
    "Signer": "joe@example.com", 
    "PkixChain": [
      {
        "Name": "joe@example.com", 
        "NotBefore": "2010-08-12T17:13:34Z", 
        "NotAfter": "2010-08-19T17:13:34Z", 
        "PublicKey": {
          "RsaExponent": "AQAB", 
          "Type": "publickey", 
          "Algorithm": "RSA-PKCS1-1.5", 
          "RsaModulus": "i0t9JRoa8atoEJUF73B3zqQsBmKBpq2vuL8M2eGRx46D8GkQavjwtLuaZccTy7JiwI8Z9AWOzJoTO2Du+0lLTQ=="
        }, 
        "Version": "1.0", 
        "Type": "certificate"
      }
    ], 
    "Type": "signature", 
    "SignatureAlgorithm": "RSA-PKCS1-1.5"
  }
}
encrypted={
  "Type": "encrypted", 
  "Recipients": [
    {
      "EncryptionAlgorithm": "RSA-PKCS1-1.5", 
      "Type": "recipient", 
      "Name": "joe@example.com", 
      "PkixCertificateHash": "TODO:HASH CERTS", 
      "EncryptionKey": "b3B7prmJYTQbOgHsqP4qzLakMibAi9QDVPkvsYU8Gty71oMOEISJqoU7cPXtvNPHRJevROPJjWDQ2jELbrqNEA=="
    }
  ], 
  "Encryption": {
    "Type": "encryption", 
    "Algorithm": "AES-256-CBC", 
    "IV": "u1tHg7WLbrbt7IovbymZ1g=="
  }, 
  "Version": "1.0", 
  "EncryptedData": "Aew9fg5Iu1GzX07/hc86kI3w8AAACcEmv0roI3EesLTaDmpVd7dWIgiT62kLvb/nHyRvDAT/ZzGB4yYa0O3tV6++xkpWvooYFMKuIZ6VoPXMxeJyFgAedELsCvf5oUZngZObiag/rTNr+C8sB8xsYw==", 
  "Integrity": {
    "Type": "integrity", 
    "Value": "GIcy/LOJmJqow8TaWLr6Z1aMY7k=", 
    "Algorithm": "HMAC-SHA1"
  }
}
