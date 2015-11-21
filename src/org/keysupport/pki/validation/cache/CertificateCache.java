package org.keysupport.pki.validation.cache;

import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.PolicyNode;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.CertID;
import org.keysupport.httpclient.PkiUri;
import org.keysupport.pki.validation.ValidationUtils;

/*
 * This class represents our certificate cache.
 * 
 * It is not quite a tree, because it represents relationships
 * with a collection of cross-certificates, where forward and
 * reverse relationships are established.  I.e., mutual cross certification.
 * 
 * However, there can be only one trust anchor.
 * 
 * Certificates are identified by issuerNameHash and issuerKeyHash.
 * 
 * Relationships are built using subject key identifier and authority key identifier.
 * 
 * If a given certificate does not have an SKI extension, an SKI value will be calculated.
 * 
 * This class only represents the cache, and will be built using cache management objects.
 */
public class CertificateCache implements Serializable {

	/**
	 * Do not change the serial below to accommodate for forward 
	 * compatibility.
	 */
	private static final long serialVersionUID = -9108050576800600587L;

	private static final Log LOG = LogFactory.getLog(CertificateCache.class);

	private volatile X509Certificate caCert = null;
	private volatile ArrayList<CertificateCache> issuedByThisCa = null;
	private volatile CertID subjectCertId = null;
	private volatile CertID issuerCertId = null;
	private volatile boolean hasIdOcsp = false;
	private volatile PkiUri[] ocspUri = null;
	private volatile boolean hasHttpCDP = false;
	private volatile PkiUri[] httpCDPUri = null;
	private volatile ConcurrentHashMap<CertID, CertificateCache> fCache = null;
	/*
	 * Working to store policy OIDs in the cache.
	 * 
	 * We are most likely to perform PKIX validation
	 * and store the entire policy tree in this
	 * certificate cache object.
	 */
	private volatile Set<ASN1ObjectIdentifier> validPolicies = null;
	private volatile PolicyNode policyTree = null;
	
	@SuppressWarnings("unused")
	private CertificateCache() {
		//Hiding the default constructor
	}
	
	public CertificateCache(X509Certificate caCert) {
		LOG.debug("Creating cache entry for: " + caCert.getSubjectX500Principal().getName());
		this.caCert = caCert;
		this.issuedByThisCa = new ArrayList<CertificateCache>();
		this.ocspUri = ValidationUtils.getOcspUris(this.caCert);
		this.hasIdOcsp = (this.ocspUri != null && this.ocspUri.length >= 1);
		this.httpCDPUri = ValidationUtils.getHttpCdpUris(this.caCert);
		this.hasHttpCDP = (this.httpCDPUri != null && this.httpCDPUri.length >= 1);
		/*
		 * For now, we are not supporting LDAP URI for revocation checking,
		 * but support may be added in the future.  For now, we will reject
		 * the CA from being placed in the cache. This does not apply to the
		 * trust anchor.
		 */
		//if (!this.isSelfSigned() && !this.hasIdOcsp && !this.hasHttpCDP) {
		//	throw new ValidationException("CA does not have OCSP URI or HTTP CDP URI defined.  Rejecting.");
		//}
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

	/**
	 * Returns the certificate held in this object.
	 * @return
	 */
	public X509Certificate getCertificate() {
		return this.caCert;
	}
	
	/**
	 * Get the CertID for the CA that signed the CA represented
	 * in this certificate cache entry.
	 * 
	 * @return the issuerCertId
	 */
	public CertID getIssuerCertId() {
		return issuerCertId;
	}

	/**
	 * Set the CertID for the CA that signed the CA represented
	 * in this certificate cache entry.
	 * 
	 * @param issuerCertId the issuerCertId to set
	 */
	public void setIssuerCertId(CertID issuerCertId) {
		this.issuerCertId = issuerCertId;
	}
	
	/**
	 * Get the CertID for the CA represented in this certificate
	 * cache entry.
	 * 
	 * @return
	 */
	public CertID getSubjectCertId() {
		return this.subjectCertId;
	}

	/**
	 * Get the CertID for the CA represented in this certificate
	 * cache entry.
	 * 
	 * @param subjectCertId
	 */
	public void setSubjectCertId(CertID subjectCertId) {
		this.subjectCertId = subjectCertId;
	}

	/**
	 * Adds a subject to our certificate cache.
	 * 
	 * @param subject
	 */
	public void addSubject(CertificateCache subject) {
		LOG.debug("Adding subject: " + subject.getCertificate().getSubjectX500Principal().getName() + " to this cache entry: " + this.caCert.getSubjectX500Principal().getName());
		this.issuedByThisCa.add(subject);
	}

	/**
	 * Returns an array list of all CertificateCache
	 * entries that are signed by the CA represented
	 * in this CertificateCache entry.
	 * 
	 * @return An ArrayList of CertificateCache objects
	 */
	public ArrayList<CertificateCache> getSubjects() {
		return this.issuedByThisCa;
	}
	
	public void setSubjects(ArrayList<CertificateCache> issuedByThisCa) {
		this.issuedByThisCa = issuedByThisCa;
	}

	/**
	 * @return the hasIdOcsp
	 */
	public boolean hasOcspAccessMethod() {
		return this.hasIdOcsp;
	}

	/**
	 * 
	 * @return an array of PkiUri objects that contain OCSP URI
	 */
	public PkiUri[] getOcspUris() {
		return this.ocspUri;
	}

	/**
	 * @return the hasHttpCDP
	 */
	public boolean hasHttpCDP() {
		return this.hasHttpCDP;
	}

	/**
	 * 
	 * @return an array of PkiUri objects that contain HTTP CDP URI
	 */
	public PkiUri[] getHttpCdpUris() {
		return this.httpCDPUri;
	}

	/**
	 * @return A String representation of this object.
	 */
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("[\n");
		sb.append("  Version: V" + this.caCert.getVersion() + "\n");
		sb.append("  Subject: " + this.caCert.getSubjectX500Principal().toString() + "\n");
		sb.append("  Signature Algorithm: " + this.caCert.getSigAlgName() + ", OID = " + this.caCert.getSigAlgOID() + "\n");
		sb.append("  Key:  " + this.caCert.getPublicKey().toString() + "\n");
		sb.append("  Validity: [From: " + this.caCert.getNotBefore().toString() + ",\n");
		sb.append("               To: " + this.caCert.getNotAfter().toString() + "]\n");
		sb.append("  Issuer: " + this.caCert.getIssuerX500Principal().toString() + "\n");
		sb.append("  SerialNumber: " + this.caCert.getSerialNumber().toString() + ", HEX=" + DataUtil.byteArrayToString(this.caCert.getSerialNumber().toByteArray()) + "\n");
		if (this.hasIdOcsp) {
			for (PkiUri uri: this.ocspUri) {
				sb.append("  HTTP: " + uri + "\n");
			}
		}
		if (this.hasHttpCDP) {
			for (PkiUri uri: this.httpCDPUri) {
				sb.append("  HTTP: " + uri + "\n");
			}
		}
		if (this.policyTree != null) {
			sb.append("  Policy Tree to Trust Anchor:");
			sb.append(this.policyTree.toString());
		}
		sb.append("]\n");
		return sb.toString();
	}

	/**
	 * @return the validPolicies
	 */
	public Set<ASN1ObjectIdentifier> getValidPolicies() {
		return validPolicies;
	}

	/**
	 * 
	 * TODO:  Perform PKIX validation on all of the issuing CAs
	 * for each of the associated policies and add each policy
	 * from the constructed policy tree.
	 * 
	 * A valid policy shall only be added by the PKIXValidator 
	 * where the policy was validated to be valid with this 
	 * cache entry.
	 * 
	 * @param validPolicy the validPolicy to add
	 */
	public void addValidPolicy(ASN1ObjectIdentifier validPolicy) {
		this.validPolicies.add(validPolicy);
	}

	/**
	 * @return the policyTree
	 */
	public PolicyNode getPolicyTree() {
		return policyTree;
	}

	/**
	 * @param policyTree the policyTree to set
	 */
	public void setPolicyTree(PolicyNode policyTree) {
		this.policyTree = policyTree;
	}

	/**
	 * This method flattens the certificate cache into a HashMap, where
	 * the key is the CertID and the object is the CertificateCache.
	 * 
	 * The flattened cache will not have any subjects, and the Trust
	 * Anchor will not be present.
	 * 
	 * This form of serialization will be used to evaluate all of our
	 * intermediate certificates.
	 * 
	 * @param cache
	 * @return HashMap of with CertID as the key, and CertificateCache
	 */
	protected synchronized ConcurrentHashMap<CertID, CertificateCache> getFlattentedCache() {
		this.fCache = new ConcurrentHashMap<CertID, CertificateCache>();
		/*
		 * Get the CA in the CertificateCache, unless it is the
		 * Trust Anchor.
		 */
		if (!this.isSelfSigned()) {
			CertificateCache entryNoSub = this;
			if (entryNoSub != null) {
				this.fCache.put(this.getSubjectCertId(), entryNoSub);
			}
		}
		/*
		 * Now that we placed this CertificateCache entry
		 * in the HashMap, we will use recursion to get
		 * the subjects.
		 */
		ArrayList<CertificateCache> subjects = this.getSubjects();
		for (CertificateCache entry: subjects) {
			ConcurrentHashMap<CertID, CertificateCache> subEntries = entry.getFlattentedCache();
			this.fCache.putAll(subEntries);
		}
		return this.fCache;
	}

}
