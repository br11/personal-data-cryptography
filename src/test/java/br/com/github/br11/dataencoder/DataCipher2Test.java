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
 * 
 * 
 *
 */
public class DataCipher2Test {

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

}
