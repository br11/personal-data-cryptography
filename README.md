# Personal Data Cryptography

## Data Privacy Module

This module provides personal data privacy end-to-end even in public networks.
The sender encrypts the data with the receiver's public key and send it. The receiver than decrypts with its private key.
Even if the means of exchange is public, the data privacy is guaranteed. 

#### Generating certificates for testing

Generating a self-signed certificate for the data receiver. Set password to 'changeittoo'.
```console
openssl req -x509 -newkey rsa:4096 \
        -keyout receiver-key.pem -out receiver-cert.pem -days 365 
```
Converting the certificate into a PKCS-12 file.
```console
openssl pkcs12 -export -in receiver-cert.pem -inkey receiver-key.pem \
        -name receiver -out receiver-cert-PKCS-12.p12 
```
Importing certificate and keys to the Java trusted store.
```console
keytool -importkeystore -deststorepass changeit -destkeystore cacerts \
        -srckeystore receiver-cert-PKCS-12.p12 -srcstoretype PKCS12 
```

Generating a self-signed certificate for the data sender. Set password to 'changeitaswell'.
```console
openssl req -x509 -newkey rsa:4096 -keyout sender-key.pem \
        -out sender-cert.pem -days 365
```
#### Unit testing
```Java
// Sender
private DataEncoder senderDataCipher;
private PublicKey receiverPublicKey;

// Receiver
private DataEncoder receiverDataCipher;

@Before
public void setUp() {
    // In the sender    
    senderDataCipher = new DataEncoder("./src/test/resources/cacerts", "my_test");
    senderDataCipher.init(() -> "changeit".toCharArray(), () -> "changeittoo".toCharArray());
    senderDataCipher.setValidateCertPath(false);
    receiverPublicKey = senderDataCipher.getPublicKey(new FileInputStream("./src/test/resources/mycert.pem"));

    // In the receiver
    receiverDataCipher = new DataEncoder("./src/test/resources/cacerts", "my_test");
    receiverDataCipher.init(() -> "changeit".toCharArray(), () -> "changeittoo".toCharArray());
    receiverDataCipher.setValidateCertPath(false);
}

@Test
public void testEncryptDecrypt() throws GeneralSecurityException, IOException {
    // In the sender
    String data = "some data";
    PublicKey receiverPublicKey = senderDataCipher.getPublicKey(new FileInputStream("./src/test/resources/mycert.pem"));
    byte[] encryptedData = senderDataCipher.encrypt(data.getBytes(), receiverPublicKey);

    // In the receiver
    byte[] decryptedData = receiverDataCipher.decrypt(encryptedData);

    // Assertions
    assertNotEquals(data, new String(encryptedData));
    assertEquals(data, new String(decryptedData));
}
```

## Digital Signature Module
[coming soon]
