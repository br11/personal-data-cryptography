# Personal Data Cryptography

## Generating certificates for testing
```console
openssl req -x509 -newkey rsa:4096 \
        -keyout mykey.pem -out mycert.pem -days 365 
```
  password: changeittoo
```console
openssl pkcs12 -export -in mycert.pem -inkey mykey.pem \
        -name my_test -out mycert-PKCS-12.p12 
```
  password: changeittoo
```console
keytool -importkeystore -deststorepass changeit -destkeystore cacerts \
        -srckeystore mycert-PKCS-12.p12 -srcstoretype PKCS12 
```
  password: changeittoo
```console
openssl req -x509 -newkey rsa:4096 -keyout otherkey.pem \
        -out othercert.pem -days 365
```
  password: changeitaswell

## Unit testing
```Java
private DataEncoder dataEncoder;
PublicKey publicKey;

@Before
public void setUp() {
    dataEncoder = new DataEncoder("./src/test/resources/cacerts", "my_test");
    dataEncoder.init(() -> "changeit".toCharArray(), () -> "changeittoo".toCharArray());
    dataEncoder.setValidateCertPath(false);
    PublicKey publicKey = dataEncoder.getPublicKey(new FileInputStream("./src/test/resources/mycert.pem"));
}

@Test
public void testEncryptDecrypt() throws GeneralSecurityException, IOException {
    // Sender side
    String data = "some data";
    PublicKey publicKey = dataEncoder.getPublicKey(new FileInputStream("./src/test/resources/mycert.pem"));
    byte[] encryptedData = dataEncoder.encrypt(data.getBytes(), publicKey);

    // Recipient side
    byte[] decryptedData = dataEncoder.decrypt(encryptedData);

    // Assertions
    assertNotEquals(data, new String(encryptedData));
    assertEquals(data, new String(decryptedData));
}
```
