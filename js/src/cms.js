/**
 * Copyright (c) 2010, Cullen Jennings, Eric Rescola, Joe Hildebrand, Matthew A. Miller, 
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

cmstng.CMS = {
     /**
     * Encrypts the given message via the CMSEP method.
     *
     * @param   {Object} key The key to encrypt with
     * @param   {String} msg The message to encrypt
     * @returns {BigInteger} The ciphertext for {msg} from {key}
     * @throws  {TypeError} If {key} is invalid
     */
    CMSEP: function(cert, msg) {
        if (!cert || !cert.e || !cert.n || !cert.name ) {
            throw new TypeError("invalid public key");
        }
        
        // form the CMK 
        cmkBits = sjcl.random.randomWords( 128 / 32 , 0 );
        cmkB64 = sjcl.codec.base64.fromBits( cmkBits );
        //console.debug( "cmkB64=" + cmkB64 );

        // encrypt the CMK 
        cmkEnc  = cmstng.RSA.RSAEP( cert, cmkB64 );
        //console.debug( "cmkEnc=" + cmkEnc );

        // TODO , fix to support multiple certs 

        // generate CEK from CMK 
        cekB64 = cmstng.KDF.P_SHA256( cmkB64 ,  "Encryption" );
        //console.debug( "cekB64=" + cekB64 );

        // encrypt the data with CEK 
        ctext  = cmstng.AES.AESEP( cekB64, msg );
        //console.debug( "ctext=" + ctext );

        cobj =  sjcl.json.decode(ctext);
        //console.debug( "cobj.iv=" + cobj.iv );
        //console.debug( "cobj.ct=" + cobj.ct );
        
        msgObj = {
            version: 1,
            name : cert.name,
            //recip : [ { 
            certHash : "TODO",
            cmkEnc : sjcl.codec.base64.toBits( cmkEnc ), 
            cmkAlgo : "RSA-PKCS1-1.5",
            //} ], 
            iv : cobj.iv,
            ct :  cobj.ct, 
            algo : "AES-128-CCM",
            kdf : "P_SHA256"
        };
        
        msg =  sjcl.json.encode( msgObj );
        //console.debug( "msg=" + msg );

        return msg;
    },
    /**
     * Decrypts the given ciphertext via the CMSDP method.
     *
     * @param   {Object} key The key to decrypt with
     * @param   {Base64} ctext The ciphertext to decrypt
     * @returns {string} The message for {ctext} from {key}
     * @throws  {TypeError} If {key} is invalid
     */
    CMSDP: function(cert, ctext) {
        var msg;
        
        if (!cert || !cert.d || !cert.n || !cert.e ) {
            throw new TypeError("invalid private key");
        }

        e = sjcl.codec.hex.fromBits( sjcl.codec.base64.toBits( cert.e ) );
        n = sjcl.codec.hex.fromBits( sjcl.codec.base64.toBits( cert.n ) );
        d = sjcl.codec.hex.fromBits( sjcl.codec.base64.toBits( cert.d ) );

        //console.debug( "cmsdec e=" + e  );
        //console.debug( "cmsdec n=" + n  );
        //console.debug( "cmsdec d=" + d  );

        // TODO - check using correct cert to decode this and find right data 

        msg =  sjcl.json.decode( ctext );
        //console.debug( "msg.name = " + msg.name  );
        //console.debug( "msg.cmkEnc = " + msg.cmkEnc  );
        //console.debug( "msg.ct = " + msg.ct  );
        //console.debug( "msg.iv = " + msg.iv  );

        ivB64 = sjcl.codec.base64.fromBits(msg.iv);
        ctB64 = sjcl.codec.base64.fromBits(msg.ct);

        // decode the CMK 
        cmkB64  = cmstng.RSA.RSADP( cert, msg.cmkEnc );
        //console.debug( "cmkB64 = " +cmkB64  );

        // generate the CEK 
        cekB64 = cmstng.KDF.P_SHA256( cmkB64 ,  "Encryption" );
        //console.debug( "cekB64 = " + cekB64 );

        // decode the data 
        msg2= '{iv:"'+ sjcl.codec.base64.fromBits(msg.iv) +'",ct:"'+ sjcl.codec.base64.fromBits(msg.ct) +'"}';
        //console.debug( "msg2 = " +msg2  );
        text  = cmstng.AES.AESDP( cekB64, msg2 );
        //console.debug( "text = " + text  );

        return text;
    }
};
})();
