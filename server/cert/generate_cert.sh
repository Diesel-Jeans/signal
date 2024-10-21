# Generate root private key
openssl genrsa -out rootCA.key 2048

# Generate self-signed root certificate
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.crt \
    -subj "/C=US/ST=Nordjylland/L=Aalborg/O=Denim/OU=IT/CN=localhost"

# Generate server private key
openssl genrsa -out server.key 2048

# Generate Certificate Signing Request (CSR)
openssl req -new -key server.key -out server.csr -config server_cert_ext.cnf

# Sign the server certificate using root certificate
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
    -out server.crt -days 365 -sha256 -extfile server_cert_ext.cnf -extensions v3_req

# Clean up
rm rootCA.key rootCA.srl server.csr