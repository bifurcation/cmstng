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

$(document).ready(function() {
    module("cmstng/rsa");
        
    test("RSA encrypt/decrypt primitives", function() {

        // yes, it's a combined key...just testing the primitives
        var key = {
            e: "010001", // public exponent 
            n: "c6df51ffb8156b287862f11866926c923393b36782eae3e8b0d4c3cb2e78eb6a381fe0e9cc91608416a8cf1f1a59d832132edab2e2d1d529d727686988594aeb",  // modulus (public)
            d: "4d0c92a95f79b4e59e16bf4ff3d58108f7c09ebe58e3865f4dbb710c143a37026631324a8312679b23e80b4bda3a76b780b18747e008efc279c7c7958ffda991" // decrption exponent (private )
        };

        key.e = sjcl.codec.base64.fromBits( sjcl.codec.hex.toBits( key.e ) );
        key.n = sjcl.codec.base64.fromBits( sjcl.codec.hex.toBits( key.n ) );
        key.d = sjcl.codec.base64.fromBits( sjcl.codec.hex.toBits( key.d ) );

        //console.debug( "key.e=" + key.e  );
        //console.debug( "key.n=" + key.n  );
        //console.debug( "key.d=" + key.d  );

        var msgExp, msgAct, ctext;

        msg    = "hello"
        ctext  = cmstng.RSA.RSAEP(key, msg );
      
        console.debug( "rsa ctext is " + ctext );

        msgDec = cmstng.RSA.RSADP(key, ctext);

        //console.debug( "rsa decode text is " + msgDec );
        
        equals( msgDec, msg, "messages equal");
        
    });
});
