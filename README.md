IdPlz
===
IdPlz is an IdP that does not need accounts to be created in Advance to login to.
It like Mailinator, but for Identity Providers (IdP)

generate openssl certificate

```sh
openssl \
    req \
    -x509 \
    -newkey rsa:4096 \
    -keyout key.pem \
    -out cert.crt \
    -sha256 \
    -days 365 \
    -nodes \
    -subj '/CN=localhost' \
    -addext "subjectAltName=DNS:example.com,DNS:www.example.net,IP:10.0.0.1"
```

print certificate

```sh
openssl \
    x509 \
    -in cert.crt \
    -text
```

print fingerprint

```sh
openssl \
    x509 \
    -fingerprint \
    -in cert.crt \
    -noout
```

