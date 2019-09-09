package br.com.github.br11.dataencoder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.util.Calendar;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

/**
 * Generating a test certificate valid for one year<br/>
 * <br/>
 * openssl req -x509 -newkey rsa:4096 -keyout mykey.pem -out mycert.pem -days
 * 365 <br/>
 * <br/>
 * keytool -import -alias my_test -storepass changeit -noprompt -keystore
 * cacerts -file cert.pem<br/>
 * &nbsp;&nbsp;&nbsp;&nbsp; > pass: changeittoo<br/>
 * <br/>
 * <br/>
 * openssl req -x509 -newkey rsa:4096 -keyout otherkey.pem -out othercert.pem
 * -days 365<br/>
 * <br/>
 * <br/>
 */
public class DataEncoderTest {

	private DataEncoder dataEncoder;

	private static final Date TODAY = Calendar.getInstance().getTime();

	private static final Date REMOTE_FUTURE;

	static {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.DAY_OF_MONTH, 730); // two years
		REMOTE_FUTURE = cal.getTime();
	}

	@Before
	public void setUp() {
		dataEncoder = new DataEncoder("./src/test/resources/cacerts", "my_test");
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
	public void testEncryptDecrypt() throws GeneralSecurityException, IOException {
		String data = "some data";

		dataEncoder.init(() -> "changeit".toCharArray(), () -> "changeittoo".toCharArray());
		dataEncoder.setValidateCertPath(false);

		PublicKey publicKey = dataEncoder.getPublicKey(new FileInputStream("./src/test/resources/mycert.pem"));

		byte[] encryptedData = dataEncoder.encrypt(data.getBytes(), publicKey);

		byte[] decryptedData = dataEncoder.decrypt(encryptedData);

		assertEquals(data, new String(decryptedData));
	}

	// @Test
	// public void testDecrypt() throws KeyStoreException, IOException,
	// GeneralSecurityException, CertificateException {
	// KeyStore trustStore = KeyStore.getInstance(DataEncoder.KEYSTORE_TYPE);
	// InputStream keyStoreStream = new
	// FileInputStream("./src/test/resources/othercert.pem");
	// trustStore.load(keyStoreStream, "changeitaswell".toCharArray());
	//
	// Enumeration<String> aliases = trustStore.aliases();
	// while(aliases.hasMoreElements()) {
	// System.out.println(aliases.nextElement());
	// }
	//
	// fail("not yet implemented");
	// }

}
