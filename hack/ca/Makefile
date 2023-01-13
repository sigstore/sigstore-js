
clean:
	rm -rf store
	rm *.crt

root.crt:
	mkdir -p store/root/ca.db.certs
	touch store/root/ca.db.index
	openssl ecparam -out store/root/ca.key -name secp384r1 -genkey
	openssl req \
	  -new \
	  -key store/root/ca.key \
		-sha384 \
		-subj /organizationName=foobar.dev/commonName=foobar \
		-addext "basicConstraints = critical, CA:true" \
		-addext "keyUsage = critical, keyCertSign, cRLSign" \
		-out store/root/ca.csr
	openssl ca \
		-notext \
		-batch \
		-selfsign \
		-config ca.conf \
		-in store/root/ca.csr \
		-out store/root/ca.crt
	cp store/root/ca.crt root.crt

int.crt: root.crt
	mkdir -p store/int/ca.db.certs
	touch store/int/ca.db.index
	openssl ecparam -out store/int/ca.key -name secp384r1 -genkey
	openssl req \
		-new \
	  -key store/int/ca.key \
		-sha384 \
		-subj /organizationName=foobar.dev/commonName=foobar-intermediate \
		-addext "keyUsage = critical, keyCertSign, cRLSign" \
		-addext "basicConstraints = critical, CA:true, pathlen:0" \
		-addext "extendedKeyUsage = codeSigning" \
		-out store/int/ca.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-in store/int/ca.csr \
		-out store/int/ca.crt
	cp store/int/ca.crt int.crt

leaf.crt: int.crt
	mkdir -p store/leaf/ca.db.certs
	touch store/leaf/ca.db.index
	openssl ecparam -out store/leaf/ca.key -name prime256v1 -genkey
	openssl req \
		-new \
	  -key store/leaf/ca.key \
		-sha384 \
		-subj / \
		-addext "keyUsage = critical, digitalSignature" \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "subjectAltName = URI:http://foobar.dev" \
		-out store/leaf/leaf.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int \
		-in store/leaf/leaf.csr \
		-out store/leaf/ca.crt
	cp store/leaf/ca.crt leaf.crt

poison.crt: int.crt
	mkdir -p store/poison
	openssl ecparam -out store/poison/cert.key -name prime256v1 -genkey
	openssl req \
		-new \
	  -key store/poison/cert.key \
		-sha384 \
		-subj / \
		-addext "keyUsage = critical, digitalSignature" \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "1.3.6.1.4.1.11129.2.4.3 = critical, ASN1:NULL:" \
		-out store/poison/poison.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int \
		-in store/poison/poison.csr \
		-out poison.crt

nosan.crt: int.crt
	mkdir -p store/nosan
	openssl ecparam -out store/nosan/cert.key -name prime256v1 -genkey
	openssl req \
		-new \
	  -key store/nosan/cert.key \
		-sha384 \
		-subj / \
		-addext "keyUsage = critical, digitalSignature" \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "1.3.6.1.4.1.57264.1.1 = DER:46:4F:4F" \
		-out store/nosan/nosan.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int \
		-in store/nosan/nosan.csr \
		-out nosan.crt

badsan.crt: int.crt
	mkdir -p store/badsan
	openssl ecparam -out store/badsan/cert.key -name prime256v1 -genkey
	openssl req \
		-new \
	  -key store/badsan/cert.key \
		-sha384 \
		-subj / \
		-addext "keyUsage = critical, digitalSignature" \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "subjectAltName = IP:192.168.1.1" \
		-out store/badsan/badsan.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int \
		-in store/badsan/badsan.csr \
		-out badsan.crt

nokeyusage.crt: int.crt
	mkdir -p store/nokeyusage
	openssl ecparam -out store/nokeyusage/cert.key -name prime256v1 -genkey
	openssl req \
		-new \
	  -key store/nokeyusage/cert.key \
		-sha384 \
		-subj / \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "subjectAltName = IP:192.168.1.1" \
		-out store/nokeyusage/nokeyusage.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int \
		-in store/nokeyusage/nokeyusage.csr \
		-out nokeyusage.crt

invalidleaf.crt: leaf.crt
	mkdir -p store/invalidleaf
	openssl ecparam -out store/invalidleaf/cert.key -name prime256v1 -genkey
	openssl req \
		-new \
	  -key store/invalidleaf/cert.key \
		-sha384 \
		-subj / \
		-addext "keyUsage = critical, digitalSignature" \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "subjectAltName = URI:http://foobar.dev" \
		-out store/invalidleaf/invalidleaf.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_leaf \
		-in store/invalidleaf/invalidleaf.csr \
		-out invalidleaf.crt

