var ca_priv={
  "PublicKey": {
    "RsaExponent": "AQAB", 
    "Type": "publickey", 
    "Algorithm": "RSA-PKCS1-1.5", 
    "RsaModulus": "mligWgVcebvxjBErwU/BRolcJOnmvtw6kUuLtGp7gkXNsYdUVRM0boAcyWc+sm9DXjfIFBDX16GaO6LEwVHWaQ=="
  }, 
  "Version": "1.0", 
  "Type": "privatekey", 
  "Algorithm": "RSA-PKCS1-1.5", 
  "PrivateExponent": "e182JV69sWyiQeSDxgxbIGexaKwyTgM5KWRqcjbfLJwcoSPk+WKD+3538jxDKBe6kU9O++y50/Utx01gG51HgQ=="
};
var ca_cert={
  "Hash": "3Zze811p4lwYvIPV/Ig0SV8ZvQE=", 
  "Name": "My CA", 
  "NotBefore": "2010-08-30T19:42:14Z", 
  "NotAfter": "2011-08-30T19:42:14Z", 
  "PublicKey": {
    "RsaExponent": "AQAB", 
    "Type": "publickey", 
    "Algorithm": "RSA-PKCS1-1.5", 
    "RsaModulus": "mligWgVcebvxjBErwU/BRolcJOnmvtw6kUuLtGp7gkXNsYdUVRM0boAcyWc+sm9DXjfIFBDX16GaO6LEwVHWaQ=="
  }, 
  "Version": "1.0", 
  "Extensions": [
    {
      "Type": "extension", 
      "Name": "urn:oid:2.5.29.15"
    }, 
    {
      "Type": "extension", 
      "Name": "urn:oid:2.5.29.15", 
      "Value": 5
    }, 
    {
      "Type": "extension", 
      "Name": "urn:oid:2.5.29.15", 
      "Value": 6
    }
  ], 
  "Serial": 0, 
  "Type": "certificate"
};
var priv={
  "PublicKey": {
    "RsaExponent": "AQAB", 
    "Type": "publickey", 
    "Algorithm": "RSA-PKCS1-1.5", 
    "RsaModulus": "umPNqBWO0F60ZdUmAMTpUbzXfOoYEIm7BeecwqqpSk0UFA6qNkegtMkHex6HeynXpjubwLKV6RVw7el7m5vx/w=="
  }, 
  "Version": "1.0", 
  "Type": "privatekey", 
  "Algorithm": "RSA-PKCS1-1.5", 
  "PrivateExponent": "abud+WCpUCi5Gx9L3JnXZWfDsfe1yQPolRPrSD65pAyWWFWtUpfEPBKLJh+4x7ZHwZOKspYVVf+QREQIHlS6uQ=="
};
var pub={
  "RsaExponent": "AQAB", 
  "Type": "publickey", 
  "Algorithm": "RSA-PKCS1-1.5", 
  "RsaModulus": "umPNqBWO0F60ZdUmAMTpUbzXfOoYEIm7BeecwqqpSk0UFA6qNkegtMkHex6HeynXpjubwLKV6RVw7el7m5vx/w=="
};
var cert={
  "Hash": "wIJfADsFJdBU04iEoGPJ92FoLKk=", 
  "Name": "joe@example.com", 
  "NotBefore": "2010-08-30T19:42:15Z", 
  "NotAfter": "2011-08-30T19:42:15Z", 
  "PublicKey": {
    "RsaExponent": "AQAB", 
    "Type": "publickey", 
    "Algorithm": "RSA-PKCS1-1.5", 
    "RsaModulus": "umPNqBWO0F60ZdUmAMTpUbzXfOoYEIm7BeecwqqpSk0UFA6qNkegtMkHex6HeynXpjubwLKV6RVw7el7m5vx/w=="
  }, 
  "Version": "1.0", 
  "Serial": 0, 
  "Type": "certificate"
};
var signed_cert={
  "SignedData": "eyJEYXRlIjogIjIwMTAtMDgtMzBUMTk6NDI6MTVaIiwgIkRhdGEiOiAie1wiSGFzaFwiOiBcIndJSmZBRHNGSmRCVTA0aUVvR1BKOTJGb0xLaz1cIiwgXCJOYW1lXCI6IFwiam9lQGV4YW1wbGUuY29tXCIsIFwiTm90QmVmb3JlXCI6IFwiMjAxMC0wOC0zMFQxOTo0MjoxNVpcIiwgXCJOb3RBZnRlclwiOiBcIjIwMTEtMDgtMzBUMTk6NDI6MTVaXCIsIFwiUHVibGljS2V5XCI6IHtcIlJzYUV4cG9uZW50XCI6IFwiQVFBQlwiLCBcIlR5cGVcIjogXCJwdWJsaWNrZXlcIiwgXCJBbGdvcml0aG1cIjogXCJSU0EtUEtDUzEtMS41XCIsIFwiUnNhTW9kdWx1c1wiOiBcInVtUE5xQldPMEY2MFpkVW1BTVRwVWJ6WGZPb1lFSW03QmVlY3dxcXBTazBVRkE2cU5rZWd0TWtIZXg2SGV5blhwanVid0xLVjZSVnc3ZWw3bTV2eC93PT1cIn0sIFwiVmVyc2lvblwiOiBcIjEuMFwiLCBcIlNlcmlhbFwiOiAwLCBcIlR5cGVcIjogXCJjZXJ0aWZpY2F0ZVwifSIsICJWZXJzaW9uIjogIjEuMCIsICJUeXBlIjogImlubmVyIiwgIkNvbnRlbnRUeXBlIjogImFwcGxpY2F0aW9uL2pzb24ifQ==", 
  "Version": "1.0", 
  "Type": "signed", 
  "Signature": {
    "Certificate": {
      "Hash": "3Zze811p4lwYvIPV/Ig0SV8ZvQE=", 
      "Name": "My CA", 
      "NotBefore": "2010-08-30T19:42:14Z", 
      "NotAfter": "2011-08-30T19:42:14Z", 
      "PublicKey": {
        "RsaExponent": "AQAB", 
        "Type": "publickey", 
        "Algorithm": "RSA-PKCS1-1.5", 
        "RsaModulus": "mligWgVcebvxjBErwU/BRolcJOnmvtw6kUuLtGp7gkXNsYdUVRM0boAcyWc+sm9DXjfIFBDX16GaO6LEwVHWaQ=="
      }, 
      "Version": "1.0", 
      "Extensions": [
        {
          "Type": "extension", 
          "Name": "urn:oid:2.5.29.15"
        }, 
        {
          "Type": "extension", 
          "Name": "urn:oid:2.5.29.15", 
          "Value": 5
        }, 
        {
          "Type": "extension", 
          "Name": "urn:oid:2.5.29.15", 
          "Value": 6
        }
      ], 
      "Serial": 0, 
      "Type": "certificate"
    }, 
    "DigestAlgorithm": "SHA1", 
    "Value": "CDpujdN3cqU/lyK6VuppzHu4054Crne/5SugD+FgAlng3t5JwQdCfw5Cja3TLV3Lee2x+QMgB//Z7fY698W9Kg==", 
    "Signer": "My CA", 
    "Type": "signature", 
    "SignatureAlgorithm": "RSA-PKCS1-1.5"
  }
};
var sig={
  "SignedData": "eyJEYXRlIjogIjIwMTAtMDgtMzBUMTk6NDI6MTVaIiwgIkRhdGEiOiAiRm9vIiwgIlZlcnNpb24iOiAiMS4wIiwgIlR5cGUiOiAiaW5uZXIiLCAiQ29udGVudFR5cGUiOiAidGV4dC9wbGFpbiJ9", 
  "Version": "1.0", 
  "Type": "signed", 
  "Signature": {
    "Certificate": {
      "SignedData": "eyJEYXRlIjogIjIwMTAtMDgtMzBUMTk6NDI6MTVaIiwgIkRhdGEiOiAie1wiSGFzaFwiOiBcIndJSmZBRHNGSmRCVTA0aUVvR1BKOTJGb0xLaz1cIiwgXCJOYW1lXCI6IFwiam9lQGV4YW1wbGUuY29tXCIsIFwiTm90QmVmb3JlXCI6IFwiMjAxMC0wOC0zMFQxOTo0MjoxNVpcIiwgXCJOb3RBZnRlclwiOiBcIjIwMTEtMDgtMzBUMTk6NDI6MTVaXCIsIFwiUHVibGljS2V5XCI6IHtcIlJzYUV4cG9uZW50XCI6IFwiQVFBQlwiLCBcIlR5cGVcIjogXCJwdWJsaWNrZXlcIiwgXCJBbGdvcml0aG1cIjogXCJSU0EtUEtDUzEtMS41XCIsIFwiUnNhTW9kdWx1c1wiOiBcInVtUE5xQldPMEY2MFpkVW1BTVRwVWJ6WGZPb1lFSW03QmVlY3dxcXBTazBVRkE2cU5rZWd0TWtIZXg2SGV5blhwanVid0xLVjZSVnc3ZWw3bTV2eC93PT1cIn0sIFwiVmVyc2lvblwiOiBcIjEuMFwiLCBcIlNlcmlhbFwiOiAwLCBcIlR5cGVcIjogXCJjZXJ0aWZpY2F0ZVwifSIsICJWZXJzaW9uIjogIjEuMCIsICJUeXBlIjogImlubmVyIiwgIkNvbnRlbnRUeXBlIjogImFwcGxpY2F0aW9uL2pzb24ifQ==", 
      "Version": "1.0", 
      "Type": "signed", 
      "Signature": {
        "Certificate": {
          "Hash": "3Zze811p4lwYvIPV/Ig0SV8ZvQE=", 
          "Name": "My CA", 
          "NotBefore": "2010-08-30T19:42:14Z", 
          "NotAfter": "2011-08-30T19:42:14Z", 
          "PublicKey": {
            "RsaExponent": "AQAB", 
            "Type": "publickey", 
            "Algorithm": "RSA-PKCS1-1.5", 
            "RsaModulus": "mligWgVcebvxjBErwU/BRolcJOnmvtw6kUuLtGp7gkXNsYdUVRM0boAcyWc+sm9DXjfIFBDX16GaO6LEwVHWaQ=="
          }, 
          "Version": "1.0", 
          "Extensions": [
            {
              "Type": "extension", 
              "Name": "urn:oid:2.5.29.15"
            }, 
            {
              "Type": "extension", 
              "Name": "urn:oid:2.5.29.15", 
              "Value": 5
            }, 
            {
              "Type": "extension", 
              "Name": "urn:oid:2.5.29.15", 
              "Value": 6
            }
          ], 
          "Serial": 0, 
          "Type": "certificate"
        }, 
        "DigestAlgorithm": "SHA1", 
        "Value": "CDpujdN3cqU/lyK6VuppzHu4054Crne/5SugD+FgAlng3t5JwQdCfw5Cja3TLV3Lee2x+QMgB//Z7fY698W9Kg==", 
        "Signer": "My CA", 
        "Type": "signature", 
        "SignatureAlgorithm": "RSA-PKCS1-1.5"
      }
    }, 
    "DigestAlgorithm": "SHA1", 
    "Value": "TP68Cy4Dr+UtdrC03FoAAj84Tb3bhQLvPqgy8JNDViKVXQB/H4YaAUcyamc8vp6TY3D2qLlgimNYlzaa2jx09A==", 
    "Signer": "joe@example.com", 
    "Type": "signature", 
    "SignatureAlgorithm": "RSA-PKCS1-1.5"
  }
};
var encrypted={
  "Type": "encrypted", 
  "Recipients": [
    {
      "EncryptionAlgorithm": "RSA-PKCS1-1.5", 
      "CertificateHash": "wIJfADsFJdBU04iEoGPJ92FoLKk=", 
      "Type": "recipient", 
      "Name": "joe@example.com", 
      "EncryptionKey": "D6kR+ajQXAx1YOUQmDXCcamsMQGsIcJ7K+l0ZcRzK5/YbEugpYVF/Z/yJ8YkW/YM3ggwPlfQyHdhB5H9jXLclA=="
    }
  ], 
  "Encryption": {
    "KDF": "P_SHA256", 
    "Type": "encryption", 
    "Algorithm": "AES-256-CBC", 
    "IV": "7675fRGu4GioZDqQHsPafA=="
  }, 
  "Version": "1.0", 
  "EncryptedData": "Gec3cGddHaKHTPk25bwYGGePn/sgn/WuBtJ0EDtVS+B5r9c/2nd62PSX+awuGES84651h4SZEptTPoIYB5qZRtq+qhSGRaUg3cwTUivvxKu+LphGVMV+qFKcbvGqxa68y6v4WNg2PpSp/UTdVR4Nwg==", 
  "Integrity": {
    "KDF": "P_SHA256", 
    "Type": "integrity", 
    "Value": "B6R75Gv6WhsP3Ak/r/eXMFY8/gw=", 
    "Algorithm": "HMAC-SHA1"
  }
};
var encrypted_pair={
  "Encryption": {
    "KDF": "PBKDF2_HMAC_SHA1", 
    "Type": "encryption", 
    "Algorithm": "AES-256-CBC", 
    "IV": "olrDK4NEGjFgatCvTap/Xw=="
  }, 
  "Integrity": {
    "KDF": "P_SHA256", 
    "Type": "integrity", 
    "Value": "a4uYDoB35FL9GOVLjj9VdRj2ODo=", 
    "Algorithm": "HMAC-SHA1"
  }, 
  "Version": "1.0", 
  "Type": "encrypted", 
  "EncryptedData": "AOueJTuL3vyqSHW7qmpXwmz1yra+V+eooDHpmyRQvsCa2M9hz5mj6i84FFSWsY/TDcKS4V8pAEEa/N4SzT9C9RIk+S70Pndq/+7xG7vJA9wpWI1plj659P3Y7QVbAuEo5AlYjJgtzkR4Wl1SF1WkADjFMHGCipvpdKWhTc62wuxT4w+fsFY8aWOHoradqJl0bl44K6O2U8/19fNalnZ4+M1P4EOQPn1BN5zz2wL0Q1pi+eteZogPnK8jThDVJ109bg8UJwmn4zQUOTiNjFfHXplnkhARe/mRbRZYe5lwEZ7HquQL0YralDNtZEZVftUWstCpjYTLoDzDV7lYWEkqv4KDxMzm3MtPLCHuI1yh5y3uSAAxB/1YblRyxDtp3O9JvacME8ULbTcY6KB5Xg5y9xiuwL5/6UfWfgYY4qY4rgRVbWm2AVbv35U9cyKT8HqZPmdE0J1n4xWRrW/n+5b8HB7cJ4gEs8uSMwVUZ7f8h7pumNZd/ndJdjmt1ByL54jmRjmbDIjZ1sxQa5Wadr00S7468NxpL/m1oMs0l8VgGwsJWAQTg/p1dNr/de5ToPrAokHvnAKkwNN9VUfwwiHbXZ2yrjGx23sVEhX483oDNL46Inxlgl+0nCn6FO/VYy3ICpkngXH4vhc5jNrGH94gM0RgAP1IOuxvFVfeWGzXiK5LlSLB0btnOYkdulKH/QSz"
};
