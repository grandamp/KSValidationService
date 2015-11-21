package org.keysupport.pki.validation.cache;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.keysupport.httpclient.PkiUri;

public class URICache {

	//TODO:  Add LOGGING!

	ConcurrentHashMap<URI, URICacheEntry> cache = null;
	
	public URICache() {
		this.cache = new ConcurrentHashMap<URI, URICacheEntry>();
	}

	public boolean isInCache(PkiUri uri) {
		return cache.containsKey(uri.getUri());
	}

	public URICacheEntry getUriCacheEntry(PkiUri uri) {
		return cache.get(uri.getUri());
	}
	
	public PkiUri[] getURIs() {
		Set<PkiUri> pUris = new HashSet<PkiUri>();
		
		URI[] uris = cache.keySet().toArray(new URI[cache.size()]);
		for (URI uri: uris) {
			pUris.add(cache.get(uri).getPkiUri());
		}
		return pUris.toArray(new PkiUri[uris.length]);
	}
	
	protected void update(PkiUri uri, URICacheEntry entry) {
		if (cache.containsKey(uri.getUri())) {
			cache.remove(uri.getUri());
		}
		entry.setPkiUri(uri);
		cache.put(uri.getUri(), entry);
	}
}
