package org.keysupport.pki.validation.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.keysupport.httpclient.PkiUri;

public class UriCacheManager {

	private static UriCacheManager instance = null;
	private volatile URICache uriCache = null;
	private static final Log LOG = LogFactory.getLog(UriCacheManager.class);

	public static synchronized UriCacheManager getInstance() {
		if (instance == null) {
			instance = new UriCacheManager();
		}
		return instance;
	}

	private UriCacheManager() {
		LOG.info("Initializing URI Cache");
		this.uriCache = new URICache();
	}
	
	/**
	 * @return the uriCache
	 */
	public synchronized URICache getUriCache() {
		return this.uriCache;
	}

	/**
	 * 
	 * 
	 * @return a copy of all URI entries in the cache with a Status Code of 200.
	 */
	public synchronized URICache getSuccessfulURICache() {
		URICache successful = new URICache();
		PkiUri[] uris = this.uriCache.getURIs();
		for (PkiUri uri: uris) {
			URICacheEntry entry = this.uriCache.getUriCacheEntry(uri);
			if (entry.getStatusCode() == 200) {
				successful.update(uri, entry);
			}
		}
		return successful;
	}
	
	/**
	 * Gets URLs that failed.
	 * 
	 * @return a copy of all URI entries in the cache with a Status Code not equal to 200.
	 */
	public synchronized URICache getFailedUriCache() {
		URICache failed = new URICache();
		PkiUri[] uris = this.uriCache.getURIs();
		for (PkiUri uri: uris) {
			URICacheEntry entry = this.uriCache.getUriCacheEntry(uri);
			if (entry.getStatusCode() != 200) {
				failed.update(uri, entry);
			}
		}
		return failed;
	}

	public void update(PkiUri uri, URICacheEntry entry) {
		this.uriCache.update(uri, entry);
	}

}
