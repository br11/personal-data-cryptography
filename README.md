# Personal Data Cryptography

## Data Confidentiality Module

This module provides personal data confidentiality end-to-end even in public networks.
Party 2 encrypts the data with the party1's public key and send it. The party1 than decrypts with its private key.
Even if the means of exchange is public, the data confidentiality is guaranteed. 

#### Generating certificates for testing

Generating a self-signed certificate for party 1 (data sender). Set password to 'changeitaswell'.
```console
openssl req -x509 -newkey rsa:4096 -keyout party1-key.pem \
        -out party1-cert.pem -days 365
```

Generating a self-signed certificate for party 2 (data receiver). Set password to 'changeittoo'.
```console
openssl req -x509 -newkey rsa:4096 \
        -keyout party2-key.pem -out party2-cert.pem -days 365 
```
Converting the certificate into a PKCS-12 file.
```console
openssl pkcs12 -export -in party2-cert.pem -inkey party2-key.pem \
        -name party2 -out party2-cert-PKCS-12.p12 
```
Importing certificate and keys to the Java trusted store.
```console
keytool -importkeystore -deststorepass changeit -destkeystore cacerts \
        -srckeystore party2-cert-PKCS-12.p12 -srcstoretype PKCS12 
```
#### Unit testing
```Java
// party1 - data sender
private DataCipher party1DataCipher;

// party2 - data receiver
private DataCipher party2DataCipher;

@Before
public void setUp() throws GeneralSecurityException, IOException {
	// at party1    
	party1DataCipher = new DataCipher("./src/test/resources/cacerts");
	party1DataCipher.init(() -> "changeit".toCharArray());
	party1DataCipher.setValidateCertPath(false);

	// at party2
	party2DataCipher = new DataCipher("./src/test/resources/cacerts", "party2");
	party2DataCipher.init(() -> "changeit".toCharArray(), () -> "changeittoo".toCharArray());
	party2DataCipher.setValidateCertPath(false);

}

@Test
public void testEncryptDecrypt() throws GeneralSecurityException, IOException {
	// at party1
	String data = "some data";
	PublicKey party1PublicKey = party1DataCipher.getPublicKey(new FileInputStream("./src/test/resources/party2-cert.pem"));
	byte[] encryptedData = party1DataCipher.encrypt(data.getBytes(), party1PublicKey);

	// at party2
	byte[] decryptedData = party2DataCipher.decrypt(encryptedData);

	// Assertions
	assertNotEquals(data, new String(encryptedData));
	assertEquals(data, new String(decryptedData));
}
```

## Digital Signature Module
[coming soon]
