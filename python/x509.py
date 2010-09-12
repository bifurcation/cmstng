from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from M2Crypto import X509
from datetime import datetime
import crypto
import string

X509V3_EXT_ERROR_UNKNOWN = (1L << 16)

def readPemFromFile(fileObj):
    substrate = ""
    start = False
    while 1:
        certLine = fileObj.readline()
        if not certLine:
            break
        if not start:
            if certLine == '-----BEGIN CERTIFICATE-----\n':
                start = True
            else:
                continue
        substrate += certLine
        if certLine == '-----END CERTIFICATE-----\n':
            return substrate

def deColon(b):
    return crypto.b64("".join([chr(int(x, 16)) for x in b.split(":")]))

def convertToJSON(cert):
    try:
        rsa = cert.get_pubkey().get_rsa()
    except ValueError:
        return None

    #  format that consists of the number's length in bytes
    #  represented as a 4-byte big-endian number, and the number
    #  itself in big-endian format, where the most significant bit
    #  signals a negative number
    n = bytes_to_long(rsa.n[4:])
    e = bytes_to_long(rsa.e[4:])
    rsa = RSA.construct((n,e))
    pub = crypto.PublicKey(key=rsa)

    c = crypto.Certificate(name=cert.get_subject().as_text().decode('utf8'),
                           pubkey=pub, 
                           serial=cert.get_serial_number(), 
                           notBefore=cert.get_not_before().get_datetime(),
                           notAfter=cert.get_not_after().get_datetime())

    for i in range(cert.get_ext_count()):
        ext = cert.get_ext_at(i)
        eid = ext.get_name()
        if eid == "UNDEF":
            continue
        ev = ext.get_value(flag=X509V3_EXT_ERROR_UNKNOWN)

        if eid == "subjectKeyIdentifier":
            ev = deColon(ev)
        elif (eid == "keyUsage") or (eid == "nsCertType") or (eid == "extendedKeyUsage"):
            ev = ev.split(", ")
        elif eid == "authorityInfoAccess":
            m = {}
            for line in ev.split("\n"):
                if line:
                    (aoid, nv) = line.split(" - ")
                    m["Access"] = aoid
                    (n, v) = nv.split(":", 1)
                    m[n] = v
            ev = m
        elif (eid == "authorityKeyIdentifier") or (eid == "certificatePolicies") or (eid == "crlDistributionPoints"):
            m = {}
            for line in ev.split("\n"):
                if line:
                    (n,v) = line.split(":", 1)
                    v = v.strip()
                    if (n == "keyid") or (n == "serial"):
                        v = deColon(v)
                    m[n.strip()] = v
            ev = m
        elif (eid == "basicConstraints") or (eid == "privateKeyUsagePeriod") or (eid == "subjectAltName") or (eid == "issuerAltName"):
            m = {}
            for line in ev.split(", "):
                if line:
                    (n,v) = line.split(":", 1)
                    v = v.strip()
                    n = n.replace(" ", "")
                    if n == "CA":
                        v = bool(v)
                    elif (n == "NotAfter") or (n == "NotBefore"):
                        v = datetime.strptime(v, "%b %d %H:%M:%S %Y GMT")
                    m[n] = v
            ev = m
            
        if ext.get_critical():
            c.addCriticalExtension(eid, ev)
        else:
            c.addExtension(eid, ev)
    return c

# Read ASN.1/PEM X.509 certificates on stdin, parse each into plain text,
# then build substrate from it
if __name__ == '__main__':
    import sys
    
    certCnt = 0

    while 1:
        substrate = readPemFromFile(sys.stdin)
        if not substrate:
            break
        cert = X509.load_cert_string(substrate)
        cert = convertToJSON(cert)
        print cert

        certCnt += 1

        print '*** %s PEM cert(s) de/serialized' % certCnt
