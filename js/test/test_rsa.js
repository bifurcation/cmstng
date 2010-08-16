/**
 * Copyright (c) 2010, Eric Rescola, Joe Hildebrand, Matthew A. Miller
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
    
    test("octet/integer conversion", function() {
        var osExp, osAct, ip;
        
        osExp = "1234";
        ip = cmstng.RSA.OS2IP(osExp);
        osAct = cmstng.RSA.I2OSP(ip, osExp.length);
        equals(osExp, osAct, "basic octet strings equal");
        
        osExp = "\x00\x01\x02\x03";
        ip = cmstng.RSA.OS2IP(osExp);
        osAct = cmstng.RSA.I2OSP(ip, osExp.length);
        equals(osExp, osAct, "0-start octet strings equal");
        
        osExp = "";
        for (var idx = 0; idx < 16; idx++) {
            osExp += String.fromCharCode(Math.random() * 256);
        }
        ip = cmstng.RSA.OS2IP(osExp);
        osAct = cmstng.RSA.I2OSP(ip, osExp.length);
        equals(osExp, osAct, "random octet strings equal");

        var caught;
        try {
            caught = false;
            var ip = cmstng.RSA.I2OSP(Math.pow(256, 16), 4);
        } catch (ex) {
            caught = (ex instanceof TypeError) && (ex.message == "integer too large");
        }
        ok(caught, "expected TypeError('integer too large') thrown");
    });
    
    test("encrypt/decrypt primitives", function() {
        var key = {
            e: BigInteger("65537"),
            n: BigInteger("8381861285539999928425167369322043075218228948622323927388630897914182086483456452515184445294706580481598631072117626969832084869558491027189130453353503"),
            d: BigInteger("5241524956364890322514741814500591900020884034993800471736091979938308504361566130855757453150201003675599948456830377244914135374650350914274340264013473")
        };
        
        // yes, it's a combined key...just testing the primitives
        var msgExp, msgAct, ctext;
        
        msgExp = cmstng.RSA.OS2IP("1234567");
        ctext = cmstng.RSA.RSAEP(key, msgExp);
        window.console.log("ctext is " + ctext.toString());
        msgAct = cmstng.RSA.RSADP(key, ctext);
        equals(msgExp.toString(), msgAct.toString(), "messages equal");
        
        var badKey, caught;
        badKey = $.extend({}, key);
        delete badKey.e;
        try {
            cmstng.RSA.RSAEP(badKey, msgExp);
        } catch (ex) {
            caught = (ex instanceof TypeError);
        }
        ok(caught, "expected TypeError thrown (missing e)");
        
        badKey = $.extend({}, key);
        delete badKey.n;
        try {
        } catch (ex) {
            caught = (ex instanceof TypeError);
        }
        ok(caught, "expected TypeError thrown (missing n)");
        
        badKey = $.extend({}, key);
        delete badKey.d;
        try {
        } catch (ex) {
            caught = (ex instanceof TypeError);
        }
        ok(caught, "expected TypeError thrown (missing d)");
    });
});
