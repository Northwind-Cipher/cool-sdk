#!/usr/bin/env sh
# Synthetic Nitro-shaped test PKI. NOT AWS. NOT a real enclave.
#
# Three P-384 certificates in the same shape as the AWS Nitro PKI (root CA →
# intermediate CA → leaf), so the verifier's positive path can be exercised
# end to end with keys and PCRs the tests control. The verifier only trusts
# this root when a test passes it explicitly as a trust bundle; the default
# bundle is the pinned AWS root.
#
# The leaf private key is committed on purpose: it is throwaway test material
# that signs nothing outside this directory's tests.
#
#   sh tests/fixtures/nitro/synthetic/generate.sh
set -eu
cd "$(dirname "$0")"
EXT=ext.tmp
trap 'rm -f ext.tmp.ca ext.tmp.leaf' EXIT
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$EXT.ca"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' > "$EXT.leaf"

openssl ecparam -name secp384r1 -genkey -noout -out root.key.pem
openssl req -new -x509 -key root.key.pem -sha384 -days 7300 -subj "/C=XX/O=CooL test/CN=synthetic.nitro-root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out root.pem

openssl ecparam -name secp384r1 -genkey -noout -out inter.key.pem
openssl req -new -key inter.key.pem -subj "/C=XX/O=CooL test/CN=synthetic.nitro-intermediate" -out inter.csr
openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key.pem -CAcreateserial -sha384 -days 7300 -extfile "$EXT.ca" -out inter.pem

openssl ecparam -name secp384r1 -genkey -noout -out leaf.key.raw.pem
openssl pkcs8 -topk8 -nocrypt -in leaf.key.raw.pem -out leaf.key.pem
openssl req -new -key leaf.key.pem -subj "/C=XX/O=CooL test/CN=synthetic.nitro-enclave" -out leaf.csr
openssl x509 -req -in leaf.csr -CA inter.pem -CAkey inter.key.pem -CAcreateserial -sha384 -days 7300 -extfile "$EXT.leaf" -out leaf.pem

# Only the certificates and the leaf signing key are kept; CA keys are discarded.
rm -f root.key.pem inter.key.pem leaf.key.raw.pem inter.csr leaf.csr root.srl inter.srl "$EXT.ca" "$EXT.leaf"
