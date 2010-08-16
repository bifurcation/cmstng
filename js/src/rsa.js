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

(function(){

var FACTOR_256 = BigInteger(256);

cmstng.RSA = {
    /**
     * Converts a octet string into a non-negative integer.
     *
     * @param   {String} os The octet string to convert
     * @return  {BigInteger} The non-negative integer for {os}
     */
    OS2IP: function(os) {
        var ip = BigInteger();

        if (!os) {
            return ip;
        }
        
        for (var idx = 0; idx < os.length; idx++) {
            var b = os.charCodeAt(idx);
            ip = BigInteger(b).multiply(FACTOR_256.pow(idx)).add(ip);
        }
        
        return ip;
    },
    /**
     * Converts a non-negative integer into an octet string.
     *
     * @param   {BigInteger|Integer|String} ip number to convert
     * @param   {Integer} len The maximum length of the octet string
     * @return  {String} The octet string for {ip}
     * @throws  {TypeError} if {ip} is greater than 256^{len}
     */
    I2OSP: function(ip, len) {
        var num = BigInteger(ip);
        if (num.compare(FACTOR_256.pow(len)) > 0) {
            throw new TypeError("integer too large");
        }
        
        var os = "";
        for (var idx = len; idx > 0; idx--) {
            var parts = num.divRem(FACTOR_256.pow(idx - 1));
            var b = parts[0].toJSValue();
            os = String.fromCharCode(b) + os;
            num = parts[1];
        }
        
        return os;
    },

    /**
     * Encrypts the given message via the RSAEP method.
     *
     * @param   {Object} key The key to encrypt with
     * @param   {BigInteger} msg The message to encrypt
     * @returns {BigInteger} The ciphertext for {msg} from {key}
     * @throws  {TypeError} If {key} is invalid
     */
    RSAEP: function(key, msg) {
        // TODO: make this broken out into chunks...
        var ctext;
        
        if (!key || !key.e || !key.n) {
            throw new TypeError("invalid key");
        }
        msg = BigInteger(msg);
        ctext = msg.modPow(key.e, key.n);
        
        return ctext;
    },
    /**
     * Decrypts the given ciphertext via the RSADP method.
     *
     * @param   {Object} key The key to decrypt with
     * @param   {BigInteger} ctext The ciphertext to decrypt
     * @returns {BigInteger} The message for {ctext} from {key}
     * @throws  {TypeError} If {key} is invalid
     */
    RSADP: function(key, ctext) {
        // TODO: make this broken out into chunks...
        var msg;
        
        if (!key || !key.d || !key.n) {
            throw new TypeError("invalid key");
        }
        ctext = BigInteger(ctext);
        msg = ctext.modPow(key.d, key.n);
        
        // TODO: try to use more expressive form if possible
        
        return msg;
    }
};
})();
