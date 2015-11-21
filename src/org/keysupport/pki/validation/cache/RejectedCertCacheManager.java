package org.keysupport.pki.validation.cache;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class RejectedCertCacheManager {

	/*
	 * As certificates are rejected (expiry/revocation/lack of HTTP based revocation)
	 * add them to the "Rejected CA" certificate cache.
	 */
	private static RejectedCertCacheManager instance = null;
	private RejectedCertCache rejectedCache = null;
	private static final Log LOG = LogFactory.getLog(RejectedCertCacheManager.class);


	public static synchronized RejectedCertCacheManager getInstance() {
		if (instance == null) {
			instance = new RejectedCertCacheManager();
		}
		return instance;
	}

	private RejectedCertCacheManager() {
		LOG.info("Initializing Rejected Certificate Cache");
		this.rejectedCache = new RejectedCertCache();
	}
	
	/**
	 * 
	 * Will check to see if the certificate is an acceptable certificate
	 * for our cache. If so, this method will return true. Otherwise,
	 * it will return false and add the certificate to the rejected
	 * certificate cache.
	 * 
	 * Currently, an a certificate is only considered "un-acceptable" if
	 * we received received it in the course of an SIA or AIA chase and
	 * it is expired, not valid yet, or revoked, or already in our rejected
	 * certificate cache.
	 * 
	 * The discovery mechanism may determine other reasons a certificate
	 * is unacceptable, but we may not want to place them in the rejected
	 * certificate cache.
	 * 
	 * @param caCert
	 * @return
	 */
	public synchronized boolean isAcceptableCA(X509Certificate caCert, String certSource) {

		/*
		 * We initially believe the certificate is valid, and therefore
		 * acceptable.
		 */
		boolean acceptable = true;
		/*
		 * Check to see if the certificate is already in our rejectedCert
		 * cache
		 */
		if (this.rejectedCache.isInCache(caCert)) {
			String reason = this.rejectedCache.getRejectedCertCacheEntry(caCert).getRejectedReason();
			LOG.info("Certificate in rejected certificate cache: " + caCert.getSubjectX500Principal().getName() + ": " + reason);
			return false;
		}
		/*
		 * Now we do a simple validity check, if not valid, an exception
		 * will be thrown.
		 */
		try {
			caCert.checkValidity();
		} catch (CertificateExpiredException | CertificateNotYetValidException e) {
			LOG.info("Certificate not valid: " + caCert.getSubjectX500Principal().getName() + ": " + e.getMessage());
			this.putRejectedCertificate(caCert, e.getMessage(), certSource);
			return false;
		}
		return acceptable;
	}

	//subjectCertId, thisCert, forkedPath, uri.toString()
	public boolean isRightDirection(byte[] ski, X509Certificate subject, Set<byte[]> currentPath, String source) {
		boolean rightDirection = false;
		/*
		 * Lets make sure the current path is established and we are 
		 * are not rejecting certs from the trust anchor.  The current
		 * path will not have any entries if we are just getting started.
		 */
		if (currentPath.isEmpty()) {
			return true;
		}
		for (byte[] pathEntry: currentPath) {
			/*
			 * We will perform a check here to ensure this is not a
			 * cross certificate back to our issuer.  If it is,
			 * we will not add it, because we only want certs in the
			 * direction of issuedByThisCa.
			 */
			if (Arrays.equals(ski, pathEntry)) {
				rightDirection = false;
				String message = "Cross Certificate in the wrong direction.";
				this.putRejectedCertificate(subject, message, source);
				break;
			} else {
				rightDirection = true;
			}
		}
		return rightDirection;
	}

	/**
	 * @return the rejectedCache
	 */
	public synchronized RejectedCertCache getRejectedCache() {
		return rejectedCache;
	}

	public synchronized void putRejectedCertificate(X509Certificate caCert, String message, String certSource) {
		RejectedCertCacheEntry entry = new RejectedCertCacheEntry(caCert, message, certSource);
		this.rejectedCache.putEntry(entry);
	}

}
