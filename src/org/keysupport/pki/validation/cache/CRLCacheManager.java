package org.keysupport.pki.validation.cache;

import java.io.ByteArrayInputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.keysupport.httpclient.HttpClient;
import org.keysupport.httpclient.HttpClientException;
import org.keysupport.httpclient.PkiUri;

public class CRLCacheManager {

	private static CRLCacheManager instance = null;
	private CRLCache crlCache = null;
	private static final Log LOG = LogFactory.getLog(CRLCacheManager.class);

	public static synchronized CRLCacheManager getInstance() {
		if (instance == null) {
			instance = new CRLCacheManager();
		}
		return instance;
	}

	private CRLCacheManager() {
		LOG.info("Initializing CRL Cache");
		this.crlCache = new CRLCache();
	}
	
	/**
	 * @return the crlCache
	 */
	public synchronized CRLCache getCRLCache() {
		return this.crlCache;
	}

	public synchronized X509CRL getCRL(PkiUri uri) throws CRLException {
		if (this.crlCache.isInCache(uri.getUri())) {
			return this.crlCache.getUriCacheEntry(uri.getUri());
		} else {
			HttpClient http = HttpClient.getInstance();
			byte[] crlBa = null;
			try {
				crlBa = http.getRequest(uri);
			} catch (HttpClientException e) {
				throw new CRLException("Error fetching CRL: " + e.getMessage(), e);
			}
			ByteArrayInputStream bais = new ByteArrayInputStream(crlBa);
			CertificateFactory cf = null;
			try {
				cf = CertificateFactory.getInstance("X509");
			} catch (CertificateException e) {
				throw new CRLException(e);
			}
			X509CRL crl = (X509CRL) cf.generateCRL(bais);
			LOG.info("Placing CRL from " + uri.getUri().toASCIIString() + " in CRL Cache");
			this.crlCache.update(uri.getUri(), crl);
			return crl;
		}
	}
}
