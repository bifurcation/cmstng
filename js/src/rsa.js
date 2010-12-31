/**
 * Copyright (c) 2010,  Cullen Jennings, Eric Rescola, Joe Hildebrand, Matthew A. Miller
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of the <ORGANIZATION> nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

(function(){

cmstng.RSA = {
     /**
     * Encrypts the given message via the RSAEP method.
     *
     * @param   {Object} key The key to encrypt with
     * @param   {String} msg The message to encrypt
     * @returns {BigInteger} The ciphertext for {msg} from {key}
     * @throws  {TypeError} If {key} is invalid
     */
    RSAEP: function(key, msg) {
        var ctext,e,n,rsa,ctextHex;
        
        if (!key || !key.e || !key.n) {
            throw new TypeError("invalid key");
        }

        e = sjcl.codec.hex.fromBits( sjcl.codec.base64.toBits( key.e ) );
        n = sjcl.codec.hex.fromBits( sjcl.codec.base64.toBits( key.n ) );
        //console.debug( "rsaenc: e=" + e  );
        //console.debug( "rsaenc: n=" + n  );
        //console.debug( "rsaenc: msg=" + msg  );

        rsa = new RSAKey();
        rsa.setPublic( n, e );
        ctextHex = rsa.encrypt(msg);
        
        //console.debug( "rsaenc: CTextHex=" + ctextHex  );
        ctext = sjcl.codec.base64.fromBits( sjcl.codec.hex.toBits( ctextHex ));
        //console.debug( "rsaenc: CTextB64=" + ctext );

        return ctext;
    },
    /**
     * Decrypts the given ciphertext via the RSADP method.
     *
     * @param   {Object} key The key to decrypt with
     * @param   {Base64} ctext The ciphertext to decrypt
     * @returns {string} The message for {ctext} from {key}
     * @throws  {TypeError} If {key} is invalid
     */
    RSADP: function(key, ctext) {
        var msg,e,n,d,rsa,ctextHex;
        
        if (!key || !key.d || !key.n) {
            throw new TypeError("invalid key");
        }

        e = sjcl.codec.hex.fromBits( sjcl.codec.base64.toBits( key.e ) );
        n = sjcl.codec.hex.fromBits( sjcl.codec.base64.toBits( key.n ) );
        d = sjcl.codec.hex.fromBits( sjcl.codec.base64.toBits( key.d ) );

        //console.debug( "rsadec e=" + e  );
        //console.debug( "rsadec n=" + n  );
        //console.debug( "rsadec d=" + d  );

        rsa = new RSAKey();
        rsa.setPrivate( n, e, d );
        if( ctext.length == 0) {
            throw new TypeError("invalid ciphertext");
        }
        //console.debug( "rsadec CTextB64=" + ctext  );
        ctextHex = sjcl.codec.hex.fromBits( sjcl.codec.base64.toBits( ctext ));
        //console.debug( "rsadec CTextHEX=" + ctextHex  );

        msg = rsa.decrypt( ctextHex );
        //console.debug( "rsadec msg=" + msg  );
        
        return msg;
    },
  /**
     * Generate a new RSA Key Pair .
     *
     * @param   {bits} Integer number of bits in key 
     * @returns {Object} Key/Cert with base64 encoding
     */
    RSAGEN: function( bits ) {
        var e,rsa,key;

        if (!bits || bits<512 || bits>2024 ) {
            throw new TypeError("invalid bits value");
        }

        e = "010001"; // public exponent in hex 
        rsa = new RSAKey();
        rsa.generate( bits, e );

        key = {};
        key.e = sjcl.codec.base64.fromBits( sjcl.codec.hex.toBits( e ) );
        key.n = sjcl.codec.base64.fromBits( sjcl.codec.hex.toBits( rsa.n.toString(16) ) );
        key.d = sjcl.codec.base64.fromBits( sjcl.codec.hex.toBits( rsa.d.toString(16) ) );

        return key;
    }
};
})();
