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

(function() {
    // 3rd party dependencies
    var deps = [
        //'http://ajax.googleapis.com/ajax/libs/jquery/1.4.2/jquery.min.js',
       'http://github.com/silentmatt/javascript-biginteger/raw/master/biginteger.js',
        'http://bitwiseshiftleft.github.com/sjcl/sjcl.js',
      //  'http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn.js',
      //  'http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn2.js',
      //  'http://www-cs-students.stanford.edu/~tjw/jsbn/rsa.js',
     //   'http://www-cs-students.stanford.edu/~tjw/jsbn/rsa2.js',
     //   'http://www-cs-students.stanford.edu/~tjw/jsbn/base64.js',
        ''
    ];
    // our sources
    var sources = [
        'src/bedrock.js',
        'src/util.js',
        'src/rsa.js',
        ''
    ];

    // determine our path...
    var pathit = function(searchBase) {
        var script = $("head script[type='text/javascript'][src$='" + searchBase + "']");
        var p = script.attr("src") || "";
        if (p === undefined || p == searchBase) {
            return [undefined, undefined];
        }
        if (p != "") {
            p = p.replace(searchBase, "");
            if (p.charAt(p.length - 1) != '/') {
                p += "/";
            }
        }
        
        return {path : p, dom : script.get(0)};
    }
    
    // load the files
    var loadit = function(list, path) {
        list = list || [];
        
        for (var idx = 0; idx < list.length; idx++) {
            var val = list[idx];
            
            if (!val) {
                continue;
            }
            if (path === undefined) {
                path = pathit(val).path;
            }
            if (path === undefined) {
                continue;
            }
            
            //document.write ensures the scripts completely load in order
            var tag = "<script type='text/javascript' src='" + path + val + "'></script>";
            document.write(tag);
        }
    };
    
    // starting info...
    var info = pathit("crypto.js");
    
    // seutp dependencies...
    loadit(deps);
    // setup files...
    loadit(sources, info.path);
})();
