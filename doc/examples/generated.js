var priv={
  "PublicKey": {
    "RsaExponent": "AQAB", 
    "Type": "publickey", 
    "Algorithm": "RSA-PKCS1-1.5", 
    "RsaModulus": "0KRfrv1lg84K1vsweRlW/biQlf3e9ZiccPMGmhDcUhtcH+0DGmd9ESN3xpcvZ56yjjVlpuXdJ+8h4Bmqnm3fZw=="
  }, 
  "Version": "1.0", 
  "Type": "privatekey", 
  "Algorithm": "RSA-PKCS1-1.5", 
  "PrivateExponent": "xu9zrE5ANOSIwWLQXSckIteQRPPDWzkgMTIH4W6iJEXpWRdA3SjBNNrOqLZhMutzNF/vV8d5ziA1XMOVEMAQgQ=="
};
var pub={
  "RsaExponent": "AQAB", 
  "Type": "publickey", 
  "Algorithm": "RSA-PKCS1-1.5", 
  "RsaModulus": "0KRfrv1lg84K1vsweRlW/biQlf3e9ZiccPMGmhDcUhtcH+0DGmd9ESN3xpcvZ56yjjVlpuXdJ+8h4Bmqnm3fZw=="
};
cert={
  "Name": "joe@example.com", 
  "NotBefore": "2010-08-15T04:35:49Z", 
  "NotAfter": "2010-08-22T04:35:49Z", 
  "PublicKey": {
    "RsaExponent": "AQAB", 
    "Type": "publickey", 
    "Algorithm": "RSA-PKCS1-1.5", 
    "RsaModulus": "0KRfrv1lg84K1vsweRlW/biQlf3e9ZiccPMGmhDcUhtcH+0DGmd9ESN3xpcvZ56yjjVlpuXdJ+8h4Bmqnm3fZw=="
  }, 
  "Version": "1.0", 
  "Type": "certificate"
}
var sig={
  "SignedData": "eyJEYXRlIjogIjIwMTAtMDgtMTVUMDQ6MzU6NDlaIiwgIkRhdGEiOiAiRm9vIiwgIlZlcnNpb24iOiAiMS4wIiwgIlR5cGUiOiAiaW5uZXIiLCAiQ29udGVudFR5cGUiOiAidGV4dC9wbGFpbiJ9", 
  "Version": "1.0", 
  "Type": "signed", 
  "Signature": {
    "DigestAlgorithm": "SHA1", 
    "Value": "apsrYI/UZjDF6GaYUsBjtksAgUq1t0PQ4FEXt4vziUgYuDr0DcvSo3a2RcTlCYnMhZZneGkvXnCPEU5D50HjmA==", 
    "Signer": "joe@example.com", 
    "PkixChain": [
      {
        "Name": "joe@example.com", 
        "NotBefore": "2010-08-15T04:35:49Z", 
        "NotAfter": "2010-08-22T04:35:49Z", 
        "PublicKey": {
          "RsaExponent": "AQAB", 
          "Type": "publickey", 
          "Algorithm": "RSA-PKCS1-1.5", 
          "RsaModulus": "0KRfrv1lg84K1vsweRlW/biQlf3e9ZiccPMGmhDcUhtcH+0DGmd9ESN3xpcvZ56yjjVlpuXdJ+8h4Bmqnm3fZw=="
        }, 
        "Version": "1.0", 
        "Type": "certificate"
      }
    ], 
    "Type": "signature", 
    "SignatureAlgorithm": "RSA-PKCS1-1.5"
  }
};
var encrypted={
  "Type": "encrypted", 
  "Recipients": [
    {
      "EncryptionAlgorithm": "RSA-PKCS1-1.5", 
      "Type": "recipient", 
      "Name": "joe@example.com", 
      "PkixCertificateHash": "TODO:HASH CERTS", 
      "EncryptionKey": "uoGTSivP3mi0+qhzmfCHoqeTbIxeMpe64TL/6zNvYSS16Pkgq9K1OC1pmd/p5UBcwuKPv12sNXaAsig9ndCUdg=="
    }
  ], 
  "Encryption": {
    "Type": "encryption", 
    "Algorithm": "AES-256-CBC", 
    "IV": "VJuFK1sRrrbeHwCvsxxGGA=="
  }, 
  "Version": "1.0", 
  "EncryptedData": "yzCjVdlSZiaI+QKNzg1GA396Ly8vZG+xAChlXhLlLeeqtF/uqVIcF791DgPOdU0/PKDF1T1jnDeUZHMlUlkpl1JHQhQvoD+s4DtWMixlr/20xF4CeTlhieddqQoGjtRsn6siqKczR3p2tNHy0IoxsQ==", 
  "Integrity": {
    "Type": "integrity", 
    "Value": "zIEca9NOoMeN7zjGeQ3e0kzrtEs=", 
    "Algorithm": "HMAC-SHA1"
  }
};
var encrypted_pair={
  "Encryption": {
    "Type": "encryption", 
    "Algorithm": "AES-256-CBC", 
    "IV": "0RNM7UQdaw1HUk483lN/jg=="
  }, 
  "Integrity": {
    "Type": "integrity", 
    "Value": "w4s1ueQ90s5Z4yAD649Q7aHJukY=", 
    "Algorithm": "HMAC-SHA1"
  }, 
  "Version": "1.0", 
  "Type": "encrypted", 
  "EncryptedData": "v0IeLPimS2weld22loZZsj/ykS99I8Xg9cWVGIiwmpCb3oHblh/+Zf/G7UcygB/F60GT7wyPHDhVd5yTAYmNEcT8JtoRUO1TuifqXcz9lggkhwftGlYZsz9MQNa1QH8n/mD9CmQuiDlCm2LHoSlA/p47TWgJ/nh6vnRUwIsEHuSWt6ZH7F0TdmefAK51Yr8sa+skSjHw2xJBBAfF/J1mKMhuyc+mnJXy4DWiVdNXBUCmjIISaey+6KCSeSlKjdhIeqZqt5LrA69gWglJQBh50k39CNtGkHc/PwuihsX6tDtRAD+kIQ72g+o2M4R4G1o3SJJcMKDMovF2Anh553+TolEdVhJAa5mkfdRPcvIOl3hpP7jK62M7/nQrCyMoOSRKswehpM6DO/OG41v8+DuSv9FSiDW12MDmKnNm70w5LHJRaZxHW7NZMFRAPR+5i8P1S2qAWu3aEaqA904Eel4H4fOpUtRpCK/0i6ldUcbH3wgc5dZORY9QfGxPbGaz90/IxE6nq3NpUYxadG9ijRs7RXmRX1ptfoXg4JO6+Bumz3SfkmI8ib8tDit4VymptYFACNlEMQ/QfMEneOmitO5JbG72RnahaeMn/sxd2DsHDMTZco+0eLAGOkitG7bXG5HNs8LSWfMszdVWyEDhbQ6v1QWeStB9L0uujdDxShYupEGYFJrAD9obiZ9fwROuvtuX"
};
