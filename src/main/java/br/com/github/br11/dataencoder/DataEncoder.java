/**
 * 
 */
package br.com.github.br11.dataencoder;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.function.Supplier;

import javax.crypto.Cipher;

/**
 * 
 * @author marcio
 *
 */
public class DataEncoder {

	public static final String KEYSTORE_TYPE = "JKS";
	public static final String CERT_TYPE = "X.509";
	public static final String ALGORITHM = "PKIX";

	private String keyStorePath;
	private String myCertAlias;

	private KeyStore trustStore;
	private KeyPair myKeys;

	private CertPathValidator certPathValidator;
	private PKIXParameters validationParameters;
	private CertPathBuilder certPathBuilder;

	/**
	 * 
	 * @param trustStorePath
	 * @param myCertAlias
	 */
	public DataEncoder(String trustStorePath, String myCertAlias) {
		this.keyStorePath = trustStorePath;
		this.myCertAlias = myCertAlias;
	}

	/**
	 * 
	 * @param trustStorePasswordCallback
	 * @param myKeysPasswordCallback
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public void init(Supplier<char[]> trustStorePasswordCallback, Supplier<char[]> myKeysPasswordCallback)
			throws GeneralSecurityException, IOException {
		loadTrustStore(trustStorePasswordCallback);
		loadMyKeys(myKeysPasswordCallback);
		initValidator();
	}

	/**
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws GeneralSecurityException
	 */
	public byte[] encrypt(byte[] data, PublicKey key) throws GeneralSecurityException {
		Cipher encryptCipher = Cipher.getInstance(key.getAlgorithm()); // "RSA/ECB/PKCS1Padding"
		encryptCipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.getEncoder().encode(encryptCipher.doFinal(data));
	}

	/**
	 * 
	 * @param data
	 * @return
	 * @throws GeneralSecurityException
	 */
	public byte[] decrypt(byte[] data) throws GeneralSecurityException {
		Cipher decryptCipher = Cipher.getInstance(myKeys.getPrivate().getAlgorithm()); // "RSA/ECB/PKCS1Padding"
		decryptCipher.init(Cipher.DECRYPT_MODE, myKeys.getPrivate());
		return decryptCipher.doFinal(Base64.getDecoder().decode(data));
	}

	/**
	 * 
	 * @param certBytes
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public PublicKey getPublicKey(byte[] certBytes) throws GeneralSecurityException, IOException {
		return validate(certBytes).getPublicKey();
	}

	/*
	 * 
	 */
	private void loadTrustStore(Supplier<char[]> trustStorePasswordCallback)
			throws GeneralSecurityException, IOException {
		if (trustStore == null) {
			trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
			InputStream keyStoreStream = new FileInputStream(keyStorePath);
			trustStore.load(keyStoreStream, trustStorePasswordCallback.get());
		}
	}

	/*
	 * 
	 */
	private void initValidator() throws GeneralSecurityException, IOException {
		certPathValidator = CertPathValidator.getInstance(ALGORITHM);
		validationParameters = new PKIXParameters(trustStore);
		validationParameters.setRevocationEnabled(true); // if you want to check CRL
		final X509CertSelector keyUsageSelector = new X509CertSelector();
		keyUsageSelector.setKeyUsage(new boolean[] { true, false, true }); // to check digitalSignature and
																			// keyEncipherment bits
		validationParameters.setTargetCertConstraints(keyUsageSelector);

		certPathBuilder = CertPathBuilder.getInstance(ALGORITHM);
	}

	/*
	 * 
	 */
	public Certificate validate(byte[] certBytes) throws GeneralSecurityException, IOException {
		X509Certificate certificateToCheck = (X509Certificate) CertificateFactory.getInstance(CERT_TYPE)
				.generateCertificate(new ByteArrayInputStream(certBytes));

		X509CertSelector certSelector = new X509CertSelector();
		certSelector.setCertificate(certificateToCheck);

		CertPathParameters certPathParameters = new PKIXBuilderParameters(trustStore, certSelector);
		CertPath certPath = certPathBuilder.build(certPathParameters).getCertPath();

		PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath,
				validationParameters);

		System.out.println(result);

		return certificateToCheck;
	}

	/**
	 * 
	 * @param certBytes
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	private void loadMyKeys(Supplier<char[]> myKeysPasswordCallback) throws GeneralSecurityException, IOException {

		Key key = trustStore.getKey(myCertAlias, myKeysPasswordCallback.get());
		if (key instanceof PrivateKey) {
			// Get certificate of public key
			Certificate cert = trustStore.getCertificate(myCertAlias);

			// Get public key
			PublicKey publicKey = cert.getPublicKey();

			// Return a key pair
			myKeys = new KeyPair(publicKey, (PrivateKey) key);
		}
	}
}
