package org.keysupport.pki.validation.cache;

import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;

import org.keysupport.pki.validation.ValidationUtils;

public class RejectedCertCache {

	//TODO:  Add LOGGING!

	ConcurrentHashMap<byte[], RejectedCertCacheEntry> cache = null;
	
	public RejectedCertCache() {
		this.cache = new ConcurrentHashMap<byte[], RejectedCertCacheEntry>();
	}

	public boolean isInCache(X509Certificate cert) {
		byte[] ski = ValidationUtils.getPkixExOneSki(cert.getPublicKey());
		return cache.containsKey(ski);
	}

	public RejectedCertCacheEntry getRejectedCertCacheEntry(X509Certificate cert) {
		byte[] ski = ValidationUtils.getPkixExOneSki(cert.getPublicKey());
		return cache.get(ski);
	}
	
	public RejectedCertCacheEntry[] getRejectedCerts() {
		return cache.values().toArray(new RejectedCertCacheEntry[cache.size()]);
	}
	
	public void putEntry(RejectedCertCacheEntry entry) {
		byte[] ski = ValidationUtils.getPkixExOneSki(entry.getRejectedCert().getPublicKey());
		cache.put(ski, entry);
	}
}
