
SRC= sjcl/core.js \
	twu/jsbn.js twu/rsa.js twu/prng4.js twu/rng.js twu/base64.js \
	src/bedrock.js src/util.js src/rsa.js src/aes.js src/kdf.js src/cms.js

.PHONY: all stats

all: jsms.js

jsms.js: jsms-nocomp.js
	cp $^ $@

jsms-nocomp.js: $(SRC) Makefile 
	cat $(SRC) > $@

# compressed targets
jsms-closure.js: jsms-nocomp.js 
	sjcl/compress/remove_constants.pl  $< | \
	java -jar sjcl/compress/compiler.jar --compilation_level ADVANCED_OPTIMIZATIONS  > $@

jsms-yui.js: jsms-nocomp.js 
	java -jar sjcl/compress/yuicompressor-2.4.2.jar $< > $@

%.js.gz: %.js
	gzip -c $^ > $@

stats: jsms-nocomp.js jsms-closure.js jsms-yui.js jsms-nocomp.js.gz jsms-closure.js.gz jsms-yui.js.gz
	@wc -c jsms-nocomp.js jsms-closure.js jsms-yui.js jsms-nocomp.js.gz jsms-closure.js.gz jsms-yui.js.gz | grep -v total | sort -n 

