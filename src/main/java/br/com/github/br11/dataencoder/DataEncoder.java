/**
 * 
 */
package br.com.github.br11.dataencoder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author marcio
 *
 */
public class DataEncoder {
	
	
	public byte[] encrypt(byte[] data, PublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm()); // "RSA/ECB/PKCS1Padding"
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.getEncoder().encode(cipher.doFinal(data));
	}

	public byte[] decrypt(byte[] data, PrivateKey key) throws NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm()); // "RSA/ECB/PKCS1Padding"
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(Base64.getDecoder().decode(data));
	}

	
	 public static void main(String[] args) throws CertificateException {
		 byte[] certBytes = new byte[10];
		 
		 final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		 
		 final X509Certificate certificateToCheck = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));

		 certificateToCheck.getPublicKey();
	 }

	 PublicKey getPublicKey(byte[] certBytes) throws GeneralSecurityException, IOException {
		 return validate(certBytes).getPublicKey();
	 }
	 
	 Certificate validate(byte[] certBytes) throws GeneralSecurityException, IOException {
		 final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

		 final X509Certificate certificateToCheck = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));

		 final KeyStore trustStore = KeyStore.getInstance("JKS");
		 InputStream keyStoreStream = new ByteArrayInputStream(new byte[100]);
		 
		 trustStore.load(keyStoreStream, "your password".toCharArray());

		 final CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
		 final X509CertSelector certSelector = new X509CertSelector();
		 certSelector.setCertificate(certificateToCheck);

		 final CertPathParameters certPathParameters = new PKIXBuilderParameters(trustStore, certSelector);
		 final CertPathBuilderResult certPathBuilderResult = certPathBuilder.build(certPathParameters);
		 final CertPath certPath = certPathBuilderResult.getCertPath();

		 final CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
		 final PKIXParameters validationParameters = new PKIXParameters(trustStore);
		 validationParameters.setRevocationEnabled(true); // if you want to check CRL
		 final X509CertSelector keyUsageSelector = new X509CertSelector();
		 keyUsageSelector.setKeyUsage(new boolean[] { true, false, true }); // to check digitalSignature and keyEncipherment bits
		 validationParameters.setTargetCertConstraints(keyUsageSelector);
		 final PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, validationParameters);

		 System.out.println(result);
		 
		 return certificateToCheck;
	 }
}
