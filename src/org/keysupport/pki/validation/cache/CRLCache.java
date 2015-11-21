package org.keysupport.pki.validation.cache;

import java.net.URI;
import java.security.cert.X509CRL;
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CRLCache {

	private static final Log LOG = LogFactory.getLog(CRLCache.class);

	ConcurrentHashMap<URI, X509CRL> cache = null;
	
	public CRLCache() {
		this.cache = new ConcurrentHashMap<URI, X509CRL>();
	}

	public boolean isInCache(URI uri) {
		return cache.containsKey(uri);
	}

	public X509CRL getUriCacheEntry(URI uri) {
		return cache.get(uri);
	}
	
	public Collection<X509CRL> getCRLs() {
		return cache.values();
	}
	
	public void update(URI uri, X509CRL entry) {
		Set<String> crits = entry.getCriticalExtensionOIDs();
		if (crits != null && crits.size() > 0) {
			StringBuffer sb = new StringBuffer();
			for (String oid: crits) {
				sb.append(oid + " ");
			}
			LOG.info("CRITICAL EXTENSION IN CRL: " + sb.toString());
		}
		if (cache.containsKey(uri)) {
			cache.remove(uri);
		}
		cache.put(uri, entry);
	}
}
