KEYDIR = store/keys
CERTDIR = store/certs
clean:
	rm -rf store
	rm *.crt

$(KEYDIR):
	mkdir -p $(KEYDIR)

$(KEYDIR)/root.key: $(KEYDIR)
	openssl ecparam -out $(KEYDIR)/root.key -name secp384r1 -genkey

$(KEYDIR)/int.key: $(KEYDIR)
	openssl ecparam -out $(KEYDIR)/int.key -name secp384r1 -genkey

$(KEYDIR)/leaf.key: $(KEYDIR)
	openssl ecparam -out $(KEYDIR)/leaf.key -name prime256v1 -genkey

$(KEYDIR)/other.key: $(KEYDIR)
	openssl ecparam -out $(KEYDIR)/other.key -name prime256v1 -genkey

# Root certificate
root.crt: $(KEYDIR)/root.key
	mkdir -p $(CERTDIR)/root/ca.db.certs
	touch $(CERTDIR)/root/ca.db.index
	openssl req \
		-new \
		-key $(KEYDIR)/root.key \
		-sha384 \
		-subj /organizationName=foobar.dev/commonName=foobar \
		-addext "basicConstraints = critical, CA:true" \
		-addext "keyUsage = critical, keyCertSign, cRLSign" \
		-out $(CERTDIR)/root/ca.csr
	openssl ca \
		-notext \
		-batch \
		-selfsign \
		-config ca.conf \
		-in $(CERTDIR)/root/ca.csr \
		-out root.crt

# Intermedia certificate - signed by root
int.crt: root.crt $(KEYDIR)/int.key
	mkdir -p $(CERTDIR)/int/ca.db.certs
	touch $(CERTDIR)/int/ca.db.index
	openssl req \
		-new \
		-key $(KEYDIR)/int.key \
		-sha384 \
		-subj /organizationName=foobar.dev/commonName=foobar-intermediate \
		-addext "keyUsage = critical, keyCertSign, cRLSign" \
		-addext "basicConstraints = critical, CA:true, pathlen:0" \
		-addext "extendedKeyUsage = codeSigning" \
		-out $(CERTDIR)/int/ca.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-in $(CERTDIR)/int/ca.csr \
		-out int.crt

# Valid leaf certificate - signed by intermediate
leaf.crt: int.crt $(KEYDIR)/leaf.key
	mkdir -p $(CERTDIR)/leaf/ca.db.certs
	touch $(CERTDIR)/leaf/ca.db.index
	openssl req \
		-new \
		-key $(KEYDIR)/leaf.key \
		-sha384 \
		-subj / \
		-addext "keyUsage = critical, digitalSignature" \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "subjectAltName = URI:http://foobar.dev,otherName:1.3.6.1.4.1.57264.1.7;UTF8:FOO" \
		-out $(CERTDIR)/leaf/leaf.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int \
		-in $(CERTDIR)/leaf/leaf.csr \
		-out leaf.crt

# Poison leaf - contain critical poison extension
poison.crt: int.crt $(KEYDIR)/leaf.key
	mkdir -p $(CERTDIR)/poison
	openssl req \
		-new \
		-key $(KEYDIR)/leaf.key \
		-sha384 \
		-subj /organizationName=foobar.dev/commonName=poison \
		-addext "basicConstraints = critical, CA:true" \
		-addext "keyUsage = critical, digitalSignature" \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "1.3.6.1.4.1.11129.2.4.3 = critical, ASN1:NULL:" \
		-out $(CERTDIR)/poison/poison.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int \
		-in $(CERTDIR)/poison/poison.csr \
		-out poison.crt

# No SAN - leaf certificate w/o subject alt name
nosan.crt: int.crt $(KEYDIR)/leaf.key
	mkdir -p $(CERTDIR)/nosan
	openssl req \
		-new \
		-key $(KEYDIR)/leaf.key \
		-sha384 \
		-subj /organizationName=foobar.dev/commonName=nosan \
		-addext "keyUsage = critical, digitalSignature" \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "1.3.6.1.4.1.57264.1.1 = DER:46:4F:4F" \
		-out $(CERTDIR)/nosan/nosan.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int \
		-in $(CERTDIR)/nosan/nosan.csr \
		-out nosan.crt

# Bad SAN - leaf certificate w/ unsupported SAN type
badsan.crt: int.crt $(KEYDIR)/leaf.key
	mkdir -p $(CERTDIR)/badsan
	openssl req \
		-new \
		-key $(KEYDIR)/leaf.key \
		-sha384 \
		-subj /organizationName=foobar.dev/commonName=badsan \
		-addext "keyUsage = critical, digitalSignature" \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "subjectAltName = IP:192.168.1.1" \
		-out $(CERTDIR)/badsan/badsan.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int \
		-in $(CERTDIR)/badsan/badsan.csr \
		-out badsan.crt

# No key usage - leaf certificate with no keyUsage extension
nokeyusage.crt: int.crt $(KEYDIR)/leaf.key
	mkdir -p $(CERTDIR)/nokeyusage
	openssl req \
		-new \
		-key $(KEYDIR)/leaf.key \
		-sha384 \
		-subj / \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "subjectAltName = IP:192.168.1.1" \
		-out $(CERTDIR)/nokeyusage/nokeyusage.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int \
		-in $(CERTDIR)/nokeyusage/nokeyusage.csr \
		-out nokeyusage.crt

# Invalid leaf - leaf signed by another leaf
invalidleaf.crt: leaf.crt $(KEYDIR)/other.key
	mkdir -p $(CERTDIR)/invalidleaf
	openssl req \
		-new \
		-key $(KEYDIR)/other.key \
		-sha384 \
		-subj / \
		-addext "keyUsage = critical, digitalSignature" \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "subjectAltName = URI:http://foobar.dev" \
		-out $(CERTDIR)/invalidleaf/invalidleaf.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_leaf \
		-in $(CERTDIR)/invalidleaf/invalidleaf.csr \
		-out invalidleaf.crt

# Invalid intermeidate certificate - signed by the valid intermediate
# certificate, but the pathlen:0 on the parent makes this cert unusable
invalidint.crt: int.crt $(KEYDIR)/other.key
	mkdir -p $(CERTDIR)/invalidint/ca.db.certs
	touch $(CERTDIR)/invalidint/ca.db.index
	openssl req \
		-new \
		-key $(KEYDIR)/other.key \
		-sha384 \
		-subj /organizationName=foobar.dev/commonName=foobar-invalid-intermediate \
		-addext "keyUsage = critical, keyCertSign, cRLSign" \
		-addext "basicConstraints = critical, CA:true, pathlen:0" \
		-addext "extendedKeyUsage = codeSigning" \
		-out $(CERTDIR)/invalidint/ca.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int \
		-in $(CERTDIR)/invalidint/ca.csr \
		-out invalidint.crt

# Invalid leaf certificiate - signed by the invalid intermeidate certificate
deepleaf.crt: invalidint.crt $(KEYDIR)/leaf.key
	mkdir -p $(CERTDIR)/deepleaf/ca.db.certs
	touch $(CERTDIR)/deepleaf/ca.db.index
	openssl req \
		-new \
		-key $(KEYDIR)/leaf.key \
		-sha384 \
		-subj / \
		-addext "keyUsage = critical, digitalSignature" \
		-addext "extendedKeyUsage = codeSigning" \
		-addext "subjectAltName = URI:http://foobar.dev,otherName:1.3.6.1.4.1.57264.1.7;UTF8:FOO" \
		-out $(CERTDIR)/deepleaf/deepleaf.csr
	openssl ca \
		-notext \
		-batch \
		-config ca.conf \
		-name ca_int2 \
		-in $(CERTDIR)/deepleaf/deepleaf.csr \
		-out deepleaf.crt
