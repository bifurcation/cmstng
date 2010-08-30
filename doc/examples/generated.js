var ca_priv={
  "PublicKey": {
    "RsaExponent": "AQAB", 
    "Type": "publickey", 
    "Algorithm": "RSA-PKCS1-1.5", 
    "RsaModulus": "hiG5SLLzT38f76kmR5V4Elu7q/utREZeqRyWwd8q9tYBVvyy0pi4OHgmHREO3bXJfeSDlrXO7Eeo6Ozlsmx1sQ=="
  }, 
  "Version": "1.0", 
  "Type": "privatekey", 
  "Algorithm": "RSA-PKCS1-1.5", 
  "PrivateExponent": "WD5fk4CHqklMTXPPB1FCiXFoaqFNQJm7NS7lz+5uaa0qLVV0VRQuPbnoNSSDkZ6HnhBvgtzxyi6bPq8sizFpQQ=="
};
var ca_cert={
  "Hash": "1dA2awxcW2OomSLTu+yYpPTHLlY=", 
  "Name": "My CA", 
  "NotBefore": "2010-08-30T19:59:30Z", 
  "NotAfter": "2011-08-30T19:59:30Z", 
  "PublicKey": {
    "RsaExponent": "AQAB", 
    "Type": "publickey", 
    "Algorithm": "RSA-PKCS1-1.5", 
    "RsaModulus": "hiG5SLLzT38f76kmR5V4Elu7q/utREZeqRyWwd8q9tYBVvyy0pi4OHgmHREO3bXJfeSDlrXO7Eeo6Ozlsmx1sQ=="
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
    "RsaModulus": "7a98E2vouqEKRt9q+4KWM9OFwJM/UiGAjju+rok4GWsZ4mNtPBkaXnBXZBbCVxE018/OiJqBKhZtan7WFxlwcw=="
  }, 
  "Version": "1.0", 
  "Type": "privatekey", 
  "Algorithm": "RSA-PKCS1-1.5", 
  "PrivateExponent": "qdNayd2uObraxuzXWcFiZMFbrc8HzT0Wx4m0oqx0ouNc5wwXwViPLmscWhJUB5vAJsxF3z76ROU+/3YbxChIoQ=="
};
var pub={
  "RsaExponent": "AQAB", 
  "Type": "publickey", 
  "Algorithm": "RSA-PKCS1-1.5", 
  "RsaModulus": "7a98E2vouqEKRt9q+4KWM9OFwJM/UiGAjju+rok4GWsZ4mNtPBkaXnBXZBbCVxE018/OiJqBKhZtan7WFxlwcw=="
};
var cert={
  "Hash": "9UsvV7zrLHgCcA8VsvIShOW8YSY=", 
  "Name": "joe@example.com", 
  "NotBefore": "2010-08-30T19:59:30Z", 
  "NotAfter": "2011-08-30T19:59:30Z", 
  "PublicKey": {
    "RsaExponent": "AQAB", 
    "Type": "publickey", 
    "Algorithm": "RSA-PKCS1-1.5", 
    "RsaModulus": "7a98E2vouqEKRt9q+4KWM9OFwJM/UiGAjju+rok4GWsZ4mNtPBkaXnBXZBbCVxE018/OiJqBKhZtan7WFxlwcw=="
  }, 
  "Version": "1.0", 
  "Serial": 0, 
  "Type": "certificate"
};
var signed_cert={
  "SignedData": "eyJEYXRlIjogIjIwMTAtMDgtMzBUMTk6NTk6MzBaIiwgIkRhdGEiOiAie1wiSGFzaFwiOiBcIjlVc3ZWN3pyTEhnQ2NBOFZzdklTaE9XOFlTWT1cIiwgXCJOYW1lXCI6IFwiam9lQGV4YW1wbGUuY29tXCIsIFwiTm90QmVmb3JlXCI6IFwiMjAxMC0wOC0zMFQxOTo1OTozMFpcIiwgXCJOb3RBZnRlclwiOiBcIjIwMTEtMDgtMzBUMTk6NTk6MzBaXCIsIFwiUHVibGljS2V5XCI6IHtcIlJzYUV4cG9uZW50XCI6IFwiQVFBQlwiLCBcIlR5cGVcIjogXCJwdWJsaWNrZXlcIiwgXCJBbGdvcml0aG1cIjogXCJSU0EtUEtDUzEtMS41XCIsIFwiUnNhTW9kdWx1c1wiOiBcIjdhOThFMnZvdXFFS1J0OXErNEtXTTlPRndKTS9VaUdBamp1K3JvazRHV3NaNG1OdFBCa2FYbkJYWkJiQ1Z4RTAxOC9PaUpxQktoWnRhbjdXRnhsd2N3PT1cIn0sIFwiVmVyc2lvblwiOiBcIjEuMFwiLCBcIlNlcmlhbFwiOiAwLCBcIlR5cGVcIjogXCJjZXJ0aWZpY2F0ZVwifSIsICJWZXJzaW9uIjogIjEuMCIsICJUeXBlIjogImlubmVyIiwgIkNvbnRlbnRUeXBlIjogImFwcGxpY2F0aW9uL2pzb24ifQ==", 
  "Version": "1.0", 
  "Type": "signed", 
  "Signature": {
    "Certificate": {
      "Hash": "1dA2awxcW2OomSLTu+yYpPTHLlY=", 
      "Name": "My CA", 
      "NotBefore": "2010-08-30T19:59:30Z", 
      "NotAfter": "2011-08-30T19:59:30Z", 
      "PublicKey": {
        "RsaExponent": "AQAB", 
        "Type": "publickey", 
        "Algorithm": "RSA-PKCS1-1.5", 
        "RsaModulus": "hiG5SLLzT38f76kmR5V4Elu7q/utREZeqRyWwd8q9tYBVvyy0pi4OHgmHREO3bXJfeSDlrXO7Eeo6Ozlsmx1sQ=="
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
    "Value": "RHWR9oBgGeDw3GahLj30XqAbzSJxZz5WXxMeAmDgeHdgqJc8/Zqda1Dp6rThdQmTEHmAw7eJAzg233g1Ug08hQ==", 
    "Signer": "My CA", 
    "Type": "signature", 
    "SignatureAlgorithm": "RSA-PKCS1-1.5"
  }
};
var sig={
  "SignedData": "eyJEYXRlIjogIjIwMTAtMDgtMzBUMTk6NTk6MzBaIiwgIkRhdGEiOiAiRm9vIiwgIlZlcnNpb24iOiAiMS4wIiwgIlR5cGUiOiAiaW5uZXIiLCAiQ29udGVudFR5cGUiOiAidGV4dC9wbGFpbiJ9", 
  "Version": "1.0", 
  "Type": "signed", 
  "Signature": {
    "Certificate": {
      "SignedData": "eyJEYXRlIjogIjIwMTAtMDgtMzBUMTk6NTk6MzBaIiwgIkRhdGEiOiAie1wiSGFzaFwiOiBcIjlVc3ZWN3pyTEhnQ2NBOFZzdklTaE9XOFlTWT1cIiwgXCJOYW1lXCI6IFwiam9lQGV4YW1wbGUuY29tXCIsIFwiTm90QmVmb3JlXCI6IFwiMjAxMC0wOC0zMFQxOTo1OTozMFpcIiwgXCJOb3RBZnRlclwiOiBcIjIwMTEtMDgtMzBUMTk6NTk6MzBaXCIsIFwiUHVibGljS2V5XCI6IHtcIlJzYUV4cG9uZW50XCI6IFwiQVFBQlwiLCBcIlR5cGVcIjogXCJwdWJsaWNrZXlcIiwgXCJBbGdvcml0aG1cIjogXCJSU0EtUEtDUzEtMS41XCIsIFwiUnNhTW9kdWx1c1wiOiBcIjdhOThFMnZvdXFFS1J0OXErNEtXTTlPRndKTS9VaUdBamp1K3JvazRHV3NaNG1OdFBCa2FYbkJYWkJiQ1Z4RTAxOC9PaUpxQktoWnRhbjdXRnhsd2N3PT1cIn0sIFwiVmVyc2lvblwiOiBcIjEuMFwiLCBcIlNlcmlhbFwiOiAwLCBcIlR5cGVcIjogXCJjZXJ0aWZpY2F0ZVwifSIsICJWZXJzaW9uIjogIjEuMCIsICJUeXBlIjogImlubmVyIiwgIkNvbnRlbnRUeXBlIjogImFwcGxpY2F0aW9uL2pzb24ifQ==", 
      "Version": "1.0", 
      "Type": "signed", 
      "Signature": {
        "Certificate": {
          "Hash": "1dA2awxcW2OomSLTu+yYpPTHLlY=", 
          "Name": "My CA", 
          "NotBefore": "2010-08-30T19:59:30Z", 
          "NotAfter": "2011-08-30T19:59:30Z", 
          "PublicKey": {
            "RsaExponent": "AQAB", 
            "Type": "publickey", 
            "Algorithm": "RSA-PKCS1-1.5", 
            "RsaModulus": "hiG5SLLzT38f76kmR5V4Elu7q/utREZeqRyWwd8q9tYBVvyy0pi4OHgmHREO3bXJfeSDlrXO7Eeo6Ozlsmx1sQ=="
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
        "Value": "RHWR9oBgGeDw3GahLj30XqAbzSJxZz5WXxMeAmDgeHdgqJc8/Zqda1Dp6rThdQmTEHmAw7eJAzg233g1Ug08hQ==", 
        "Signer": "My CA", 
        "Type": "signature", 
        "SignatureAlgorithm": "RSA-PKCS1-1.5"
      }
    }, 
    "DigestAlgorithm": "SHA1", 
    "Value": "x6e1v+J30Hf/MPOu76SjLQaiWe8t9YcsKAxTqfo7LUgr7Hs7BPlsgfnL1i6j7pajdBnYFUSWMmbRTcEaThClbA==", 
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
      "CertificateHash": "9UsvV7zrLHgCcA8VsvIShOW8YSY=", 
      "Type": "recipient", 
      "Name": "joe@example.com", 
      "EncryptionKey": "LDqD+PXOF8HWv6u1ZoJmTIMx44Kt802s6Q8vGLqVX4yHXh44Ai5Olq5xRH6oTRsoz4BNklMbsUzXA4khwgSXpw=="
    }
  ], 
  "Encryption": {
    "KDF": "P_SHA256", 
    "Type": "encryption", 
    "Algorithm": "AES-256-CBC", 
    "IV": "vKKQpCpWqoDRplxMTANyZA=="
  }, 
  "Version": "1.0", 
  "EncryptedData": "++VBKi06VQw0tqsqFPh7XVfMwIc5AT/DkZQ7Udg0NTFMBRW3JdDWw1g7CwbMOZdyX1jZ0UYp92RvHRm7tnr/AREFTtiYOfEkUiMXAAYCjOGedbojBXy2zBbUV1KYF5VxlbNWzC5uOEdacjt/HTluLA==", 
  "Integrity": {
    "KDF": "P_SHA256", 
    "Type": "integrity", 
    "Value": "6K05R5pw9pyUNV/dEIAzDNC0CC8=", 
    "Algorithm": "HMAC-SHA1"
  }
};
var encrypted_pair={
  "Encryption": {
    "KDF": "PBKDF2_HMAC_SHA1", 
    "Type": "encryption", 
    "Algorithm": "AES-256-CBC", 
    "IV": "BAqfzy48w/R5yeEDf98svw=="
  }, 
  "Integrity": {
    "KDF": "P_SHA256", 
    "Type": "integrity", 
    "Value": "mp8yFiw9w8yBf177AJR+tyN2XBo=", 
    "Algorithm": "HMAC-SHA1"
  }, 
  "Version": "1.0", 
  "Type": "encrypted", 
  "EncryptedData": "eC4GBQwzH1j/zsqeGqHBMj5RdsUJpTnetvxCx4igBgmhfoBdqHVdLWXHfCJYOGrucklyjnPwYjAgyE0LgjB9n8/6j6Kp25qEOBkbVrWacpRfvzGJrypyjVuMryvg8JAUVBA92+PX+MhoMXoemWOZ6OOoFJTqcgh7KKnPAXasArRV1UtsIfTX1tWu6ZXoXdJfN5z1yOaStExWP8LGKcLx95M/qQf0SDJcpvzAYnlZAldAT9Ml6a5oEjtfT7e3/lTnJsCaSIBjprb+arKS782EqMr9nAj2PekMMESTmKGnh/0jjl+MybKqpMO57NeUtRKuHO323Qlui55s7VlCKh+B/F7OfJW7g2acXa7lIu80+1BrdYDen/DBflroV17M1R7VrETnDUvJw5VEp3hOvHaBz2k6VwuuvgJBc9aXgb33HASMPQCa61o2ttAod7Ca10kJkMYD8hxB1O8qHXfOdxndKBoSe6L0/tkFH9hU1Gnw4V7I1kQzS3HAmpQm3oWlnb3a8xAcIJm/9C1ZWWhsqN0ASpGUsc+aW+vByo5a+r+yhVw/bFS/HxKH9Wj2bZkubu/WyfhPYMfcBD9TTTu7sgEqANKl7xHu2UTSQmrOA5QFMaeW191RrhBtYUkHldxZqePkO8DeyZxcSDJOdHla/bF5mWTAgKODOG/z1mWNZd4pMLhpdLq2FweCD6cblPv8Y/AZ"
};
