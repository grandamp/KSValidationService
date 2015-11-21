package org.keysupport.pki.validation.cache;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

/*
 * Represents a CA in our cache
 */
public class CAEntry {

	//TODO: Almost ready to retire!

	/*
	 * TODO:
	 * Most of the methods in this class should not be in here due to bloat.
	 * These methods will be used to evaluate and populate data structures in this object,
	 * and are better suited for being in another class.
	 */
	private X509Certificate caCert = null;
	
	@SuppressWarnings("unused")
	private CAEntry() {
		//Hidden Constructor
	}

	public CAEntry(X509Certificate caCert) throws CertificateCacheException {
		if (!isCa(caCert)) {
			throw new CertificateCacheException("Certificate is not a CA certificate.");
		}
		this.caCert = caCert;
	}

	public static boolean isCa(X509Certificate caCert) {
		if (caCert.getBasicConstraints()>-1) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @return the caCert
	 */
	public X509Certificate getCaCert() {
		return caCert;
	}

	public boolean isThisCA(X509Certificate caCert) {
		return this.caCert.equals(caCert);
	}
	
	public boolean isSignedBy(X509Certificate caCert) {
			try {
				this.caCert.verify(caCert.getPublicKey());
			} catch (InvalidKeyException | CertificateException
					| NoSuchAlgorithmException | NoSuchProviderException
					| SignatureException e) {
				return false;
			}
			return true;
	}

	public boolean isSignerOf(X509Certificate caCert) {
		try {
			caCert.verify(this.caCert.getPublicKey());
		} catch (InvalidKeyException | CertificateException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			return false;
		}
		return true;
	}
	
	public boolean isSelfSigned() {
		try {
			this.caCert.verify(this.caCert.getPublicKey());
		} catch (InvalidKeyException | CertificateException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			return false;
		}
		return true;
	}

	public boolean isValid() {
		try {
			this.caCert.checkValidity();
		} catch (CertificateExpiredException | CertificateNotYetValidException e) {
			return false;
		}
		return true;
	}
	
	public boolean isRevoked(X509CRL crl) {
		return crl.isRevoked(this.caCert);
	}
	
	public boolean isSignerOf(X509CRL crl) {
		try {
			crl.verify(caCert.getPublicKey());
		} catch (InvalidKeyException | CRLException | NoSuchAlgorithmException
				| NoSuchProviderException | SignatureException e) {
			return false;
		}
		return true;
	}
	
	public byte[] getAssertedSKI() {
		byte[] extBytes = null;
		caCert.getExtensionValue("2.5.29.14");
		if ((extBytes = caCert.getExtensionValue("2.5.29.14")) != null) {
			byte[] extOctetString = ASN1OctetString.getInstance(extBytes).getOctets();
			return SubjectKeyIdentifier.getInstance(extOctetString).getKeyIdentifier();
		} else {
			return null;
		}
	}
		
	//"2.5.29.35"
	public byte[] getAssertedAKI() {
		byte[] extBytes = null;
		if ((extBytes = caCert.getExtensionValue(Extension.authorityKeyIdentifier.getId())) != null) {
			byte[] extOctetString = ASN1OctetString.getInstance(extBytes).getOctets();
			return AuthorityKeyIdentifier.getInstance(extOctetString).getKeyIdentifier();
		} else {
			return null;
		}
	}

	
}
