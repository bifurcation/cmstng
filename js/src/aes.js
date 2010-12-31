/**
 * Copyright (c) 2010,  Cullen Jennings, Eric Rescola, Joe Hildebrand, Matthew A. Miller,
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

cmstng.AES = {
     /**
     * Encrypts the given message via the AESEP method.
     *
     * @param   {Object} key The key with CEK in base64 to encrypt with
     * @param   {String} msg The message to encrypt
     * @returns {Object} The ciphertext for {msg} from {key}
     * @throws  {TypeError} If {key} is invalid
     */
    AESEP: function( cek, msg) {
        var ctext,cekBits,k,p,rp;
        
        if (!cek ) {
            throw new TypeError("invalid key");
        }

        rp = {};
        p = {
            ks : 128 , // key size 
            ts : 64 // tag size 
        };
        cekBits = sjcl.codec.base64.toBits( cek );
        k = cekBits.slice(0,p.ks/32);
        ctext  = sjcl.encrypt( k, msg, p, rp );
        
        return ctext;
    },
    /**
     * Decrypts the given ciphertext via the AESDP method.
     *
     * @param   {Object} key The key to decrypt with
     * @param   {BigInteger} ctext The ciphertext to decrypt
     * @returns {string} The message for {ctext} from {key}
     * @throws  {TypeError} If {key} is invalid
     */
    AESDP: function( cek, ctext) {
        // TODO: make this broken out into chunks...
        var msg,cekBits,k,p;
        
        if (!cek ) {
            throw new TypeError("invalid key");
        }
        
        p = {
            ks : 128  // key size 
        };

        cekBits = sjcl.codec.base64.toBits( cek );
        k = cekBits.slice(0,p.ks/32);
        msg = sjcl.decrypt( k, ctext );

        return msg;
    }
};
})();
