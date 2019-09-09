/**
 * 
 */
package br.com.github.br11.dataencoder;

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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.function.Supplier;

import javax.crypto.Cipher;

/**
 * DataEncoder
 * 
 * <br/>
 * // <br/>
 * DataEncoder enc = new DataEncoder("truststore.pks", "mycertAlias"); <br/>
 * enc.init(...); <br/>
 * <br/>
 * // Encrypting data with the recipient public key<br/>
 * byte[] encData = enc.encrypt(data, recipientPublicKey); <br/>
 * <br/>
 * // decrypting data with my private key<br/>
 * byte[] data = enc.decrypt(encData); <br/>
 * <br/>
 * <br/>
 */
public class DataEncoder {

	public static final String KEYSTORE_TYPE = "JKS";
	public static final String CERT_TYPE = "X.509";
	public static final String ALGORITHM = "PKIX";

	private String trustStorePath;
	private String mykeyStorePath;
	private String myCertAlias;

	private KeyStore trustStore;
	private KeyPair myKeys;

	private CertPathValidator certPathValidator;
	private PKIXParameters validationParameters;
	private CertPathBuilder certPathBuilder;

	private boolean validateCertPath = true;

	/**
	 * 
	 * @param trustStorePath
	 * @param myCertAlias
	 */
	public DataEncoder(String trustStorePath, String myCertAlias) {
		this.trustStorePath = trustStorePath;
		this.myCertAlias = myCertAlias;
	}

	/**
	 * 
	 * @return
	 */
	public boolean isValidateCertPath() {
		return validateCertPath;
	}

	public DataEncoder setValidateCertPath(boolean validateCertPath) {
		this.validateCertPath = validateCertPath;
		return this;
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
	public PublicKey getPublicKey(InputStream certDataStream) throws GeneralSecurityException, IOException {
		return validate(certDataStream, Calendar.getInstance().getTime()).getPublicKey();
	}

	/*
	 * 
	 */
	protected void loadTrustStore(Supplier<char[]> trustStorePasswordCallback)
			throws GeneralSecurityException, IOException {
		trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
		InputStream keyStoreStream = new FileInputStream(trustStorePath);
		trustStore.load(keyStoreStream, trustStorePasswordCallback.get());
	}

	/*
	 * 
	 */
	protected void loadMyKeys(Supplier<char[]> myKeysPasswordCallback) throws GeneralSecurityException, IOException {
		Key key = trustStore.getKey(myCertAlias, myKeysPasswordCallback.get());
		if (key instanceof PrivateKey) {
			myKeys = new KeyPair(trustStore.getCertificate(myCertAlias).getPublicKey(), (PrivateKey) key);
		}
	}

	/*
	 * 
	 */
	protected void initValidator() throws GeneralSecurityException, IOException {
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
	protected X509Certificate getCertificate(InputStream certDataStream) throws CertificateException {
		X509Certificate certificateToCheck = (X509Certificate) CertificateFactory.getInstance(CERT_TYPE)
				.generateCertificate(certDataStream);
		return certificateToCheck;
	}

	/*
	 * 
	 */
	protected X509Certificate validate(InputStream certDataStream) throws GeneralSecurityException, IOException {
		return validate(getCertificate(certDataStream), Calendar.getInstance().getTime());
	}

	/*
	 * 
	 */
	protected X509Certificate validate(InputStream certDataStream, Date validity)
			throws GeneralSecurityException, IOException {
		return validate(getCertificate(certDataStream), validity);
	}

	/*
	 * 
	 */
	protected X509Certificate validate(X509Certificate certificate) throws GeneralSecurityException, IOException {
		return validate(certificate, Calendar.getInstance().getTime());
	}

	/*
	 * 
	 */
	protected X509Certificate validate(X509Certificate certificate, Date validity)
			throws GeneralSecurityException, IOException {
		certificate.checkValidity(validity);

		if (isValidateCertPath()) {
			X509CertSelector certSelector = new X509CertSelector();
			certSelector.setCertificate(certificate);

			CertPathParameters certPathParameters = new PKIXBuilderParameters(trustStore, certSelector);
			CertPath certPath = certPathBuilder.build(certPathParameters).getCertPath();

			PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath,
					validationParameters);
			result.getPublicKey();
		}

		return certificate;
	}

}
