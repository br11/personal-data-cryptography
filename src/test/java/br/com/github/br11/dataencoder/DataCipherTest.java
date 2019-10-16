package br.com.github.br11.dataencoder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.util.Calendar;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

/**
 * # Generating certificates for testing<br/>
 * <br/>
 * openssl req -x509 -newkey rsa:4096 -keyout mykey.pem -out mycert.pem -days
 * 365 <br/>
 * &nbsp;&nbsp;&nbsp;&nbsp; > key password: changeittoo<br/>
 * <br/>
 * openssl pkcs12 -export -in mycert.pem -inkey mykey.pem -name my_test -out
 * mycert-PKCS-12.p12 <br/>
 * &nbsp;&nbsp;&nbsp;&nbsp; > key password: changeittoo<br/>
 * <br/>
 * keytool -importkeystore -deststorepass changeit -destkeystore cacerts
 * -srckeystore mycert-PKCS-12.p12 -srcstoretype PKCS12 <br/>
 * &nbsp;&nbsp;&nbsp;&nbsp; > key password: changeittoo<br/>
 * <br/>
 * openssl req -x509 -newkey rsa:4096 -keyout otherkey.pem -out othercert.pem
 * -days 365<br/>
 * &nbsp;&nbsp;&nbsp;&nbsp; > key password: changeitaswell<br/>
 * <br/>
 */
public class DataCipherTest {

	private DataCipher dataEncoder;

	private static final Date TODAY = Calendar.getInstance().getTime();

	private static final Date REMOTE_FUTURE;

	static {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.DAY_OF_MONTH, 730); // two years
		REMOTE_FUTURE = cal.getTime();
	}

	@Before
	public void setUp() {
		dataEncoder = new DataCipher("./src/test/resources/cacerts", "my_test");
	}

	@Test
	public void testLoadTrustStore() throws GeneralSecurityException, IOException {
		dataEncoder.loadTrustStore(() -> "changeit".toCharArray());
	}

	@Test
	public void testLoadMyKeys() throws GeneralSecurityException, IOException {
		dataEncoder.loadTrustStore(() -> "changeit".toCharArray());

		dataEncoder.loadMyKeys(() -> "changeittoo".toCharArray());
	}

	@Test
	public void testInitValidator() throws GeneralSecurityException, IOException {
		dataEncoder.loadTrustStore(() -> "changeit".toCharArray());
		dataEncoder.loadMyKeys(() -> "changeittoo".toCharArray());

		dataEncoder.initValidator();
	}

	@Test
	public void testValidate() throws GeneralSecurityException, IOException {
		dataEncoder.loadTrustStore(() -> "changeit".toCharArray());
		dataEncoder.loadMyKeys(() -> "changeittoo".toCharArray());
		dataEncoder.initValidator();

		dataEncoder.setValidateCertPath(false);
		dataEncoder.validate(new FileInputStream("./src/test/resources/othercert.pem"), TODAY);
	}

	@Test(expected = CertificateExpiredException.class)
	public void testValidateFalse() throws GeneralSecurityException, IOException {
		dataEncoder.loadTrustStore(() -> "changeit".toCharArray());
		dataEncoder.loadMyKeys(() -> "changeittoo".toCharArray());
		dataEncoder.initValidator();

		dataEncoder.setValidateCertPath(false);
		dataEncoder.validate(new FileInputStream("./src/test/resources/othercert.pem"), REMOTE_FUTURE);
	}

	@Test
	public void testInit() throws GeneralSecurityException, IOException {
		dataEncoder.init(() -> "changeit".toCharArray(), () -> "changeittoo".toCharArray());
	}

	@Test
	public void testGetPublicKey() throws GeneralSecurityException, IOException {
		dataEncoder.init(() -> "changeit".toCharArray(), () -> "changeittoo".toCharArray());

		dataEncoder.setValidateCertPath(false);
		PublicKey publicKey = dataEncoder.getPublicKey(new FileInputStream("./src/test/resources/othercert.pem"));
		assertNotNull(publicKey);
	}

	@Test
	public void testEncrypt() throws KeyStoreException, IOException, GeneralSecurityException, CertificateException {
		dataEncoder.init(() -> "changeit".toCharArray(), () -> "changeittoo".toCharArray());
		dataEncoder.setValidateCertPath(false);
		
		PublicKey publicKey = dataEncoder.getPublicKey(new FileInputStream("./src/test/resources/othercert.pem"));

		String data = "some data";
		byte[] encryptedData = dataEncoder.encrypt(data.getBytes(), publicKey);

		assertNotEquals(data, new String(encryptedData));
	}

	@Test
	public void testEncryptDecrypt() throws GeneralSecurityException, IOException {
		dataEncoder.init(() -> "changeit".toCharArray(), () -> "changeittoo".toCharArray());
		dataEncoder.setValidateCertPath(false);

		PublicKey publicKey = dataEncoder.getPublicKey(new FileInputStream("./src/test/resources/mycert.pem"));

		String data = "some data";
		byte[] encryptedData = dataEncoder.encrypt(data.getBytes(), publicKey);
		byte[] decryptedData = dataEncoder.decrypt(encryptedData);

		assertNotEquals(data, new String(encryptedData));
		assertEquals(data, new String(decryptedData));
	}

}
