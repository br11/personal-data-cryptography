# Personal Data Cryptography

## Data Privacy Module

This module provides personal data privacy end-to-end even in public networks.
Party 2 encrypts the data with the party1's public key and send it. The party1 than decrypts with its private key.
Even if the means of exchange is public, the data privacy is guaranteed. 

#### Generating certificates for testing

Generating a self-signed certificate for party 1 (data receiver). Set password to 'changeittoo'.
```console
openssl req -x509 -newkey rsa:4096 \
        -keyout party1-key.pem -out party1-cert.pem -days 365 
```
Converting the certificate into a PKCS-12 file.
```console
openssl pkcs12 -export -in party1-cert.pem -inkey party1-key.pem \
        -name party1 -out party1-cert-PKCS-12.p12 
```
Importing certificate and keys to the Java trusted store.
```console
keytool -importkeystore -deststorepass changeit -destkeystore cacerts \
        -srckeystore party1-cert-PKCS-12.p12 -srcstoretype PKCS12 
```

Generating a self-signed certificate for party 2 (data sender). Set password to 'changeitaswell'.
```console
openssl req -x509 -newkey rsa:4096 -keyout party2-key.pem \
        -out party2-cert.pem -days 365
```
#### Unit testing
```Java
// party2
private DataEncoder party2DataCipher;

// party1
private DataEncoder party1DataCipher;

@Before
public void setUp() {
    // In the party2    
    party2DataCipher = new DataEncoder("./src/test/resources/cacerts");
    party2DataCipher.init(() -> "changeit".toCharArray());
    party2DataCipher.setValidateCertPath(false);

    // In the party1
    party1DataCipher = new DataEncoder("./src/test/resources/cacerts", "party1");
    party1DataCipher.init(() -> "changeit".toCharArray(), () -> "changeittoo".toCharArray());
    party1DataCipher.setValidateCertPath(false);
}

@Test
public void testEncryptDecrypt() throws GeneralSecurityException, IOException {
    // In the party2
    String data = "some data";
    PublicKey party1PublicKey = party2DataCipher.getPublicKey(new FileInputStream("./src/test/resources/party1.pem"));
    byte[] encryptedData = party2DataCipher.encrypt(data.getBytes(), party1PublicKey);

    // In the party1
    byte[] decryptedData = party1DataCipher.decrypt(encryptedData);

    // Assertions
    assertNotEquals(data, new String(encryptedData));
    assertEquals(data, new String(decryptedData));
}
```

## Digital Signature Module
[coming soon]
