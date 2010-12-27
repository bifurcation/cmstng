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

$(document).ready(function() {
    module("cmstng/kdf");
      
    test("HMAC_SHA256 primitives", function() {

        // this test data from section 4.2 of RFC 4231 
        secret =  sjcl.codec.hex.toBits("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        data = sjcl.codec.hex.toBits("4869205468657265");

        hmac = cmstng.KDF.HMAC_SHA256( secret, data );

        hmacHex =  sjcl.codec.hex.fromBits( hmac );
        console.debug( "hmac is " +hmacHex );

        equals( hmacHex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "messages equal");
     
    });
  
    test("P_SHA256 primitives", function() {

        var key = {
            cmk : "MTIzNDU2NzgxMjM0NTY3OAo="
        };

        console.debug( "CMK is " + key.cmk );

        key.cek = cmstng.KDF.P_SHA256( key.cmk ,  "Encryption" );

        console.debug( "CEK is " + key.cek );

        equals( key.cek, "95yyAo3/1j/h9mHHP3kBiA==", "messages equal");
     
    });
});
