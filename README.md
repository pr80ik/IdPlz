IdPlz
===
IdPlz is an IdP that does not need accounts to be created in Advance to login to.
It like Mailinator, but for Identity Providers (IdP)

generate openssl certificate
---

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

using java keytool

```sh
keytool -genkeypair -alias idpkey -keyalg RSA -keysize 2048 \
       -keystore src/main/resources/keystore/idp-keystore.jks \
       -validity 3650 \
       -storepass idpsecret -keypass idpsecret \
       -dname "CN=id-plz, OU=Test IdP, O=Example Corp, L=TestCity, ST=TestState, C=US"

```

project structure
---

```
id-plz/
├── pom.xml
└── src/
   ├── main/
   │   ├── java/
   │   │   └── com/
   │   │       └── example/
   │   │           └── idplz/
   │   │               ├── IdPlzApplication.java
   │   │               ├── config/
   │   │               │   ├── SecurityConfig.java
   │   │               │   ├── SamlIdpConfig.java      // IdP specific properties
   │   │               │   └── OpenSamlConfig.java     // Initialize OpenSAML
   │   │               ├── controller/
   │   │               │   ├── IdpController.java      // Handles SAML SSO, login page
   │   │               │   └── MetadataController.java // Serves IdP metadata
   │   │               ├── dto/
   │   │               │   └── SamlLoginRequest.java // Form backing object
   │   │               └── service/
   │   │                   ├── SamlResponseGenerator.java
   │   │                   └── KeystoreService.java    // To load signing credentials
   │   ├── resources/
   │   │   ├── application.properties
   │   │   ├── templates/
   │   │   │   └── login.html
   │   │   └── keystore/
   │   │       └── idp-keystore.jks       // Keystore with IdP signing key
   └── test/
       └── java/

```
