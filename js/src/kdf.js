/**
 * Copyright (c) 2010, Cullen Jennings, Eric Rescola, Joe Hildebrand, Matthew A. Miller
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

cmstng.KDF = {
     /**
     * Dervices keys from master key using P_SHA256 KDF 
     *
     * @param   {Object} key CMK in base64 
     * @param   {String} the label in UTF8  
     * @returns none
     * @throws  {TypeError} If {key} is invalid
     */
    P_SHA256: function(key,label) {

        if (!key ) {
            throw new TypeError("invalid key");
        }

        // TODO - this function needs review and is likely wrong. I don't undertand the "seed" part in spec

        secret = sjcl.codec.base64.toBits( key );
        seed = sjcl.codec.utf8String.toBits( label );
        A0 = seed;
        A1 = cmstng.KDF.HMAC_SHA256( secret, A0 );
        P1 = cmstng.KDF.HMAC_SHA256( secret, sjcl.bitArray.concat(A1,seed) );
        cekBits = P1.slice(0,128/32);

        return sjcl.codec.base64.fromBits( cekBits );
    },
 /**
     * Compute HMAC with SHA256 
     *
     * @param key is "bits" object   
     * @param  data is an array of "bits" objects  
     * @returns 
     */
    HMAC_SHA256: function(key,data) {
        hmac = new sjcl.misc.hmac(key, sjcl.hash.sha256);
        ret = hmac.encrypt( data );
        return ret;
    }
};
})();
