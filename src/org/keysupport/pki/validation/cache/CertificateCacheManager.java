package org.keysupport.pki.validation.cache;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.keysupport.pki.validation.PKIXValidatorException;
import org.keysupport.pki.validation.ValidationException;
import org.keysupport.pki.validation.ValidationUtils;

public class CertificateCacheManager {

	private volatile static CertificateCacheManager instance = null;
	private volatile CertificateCache cache = null;
	private volatile ConcurrentHashMap<CertID, CertificateCache> fCache = null;
	private static final Log LOG = LogFactory.getLog(CertificateCacheManager.class);

	/*
	 * TODO: Move the following to properties
	 */
	private static String COMMON_SHA2_PEM = "-----BEGIN CERTIFICATE-----\n"
			+ "MIIEYDCCA0igAwIBAgICATAwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx\n"
			+ "GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE\n"
			+ "AxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTEwMTIwMTE2NDUyN1oXDTMw\n"
			+ "MTIwMTE2NDUyN1owWTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu\n"
			+ "bWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UEAxMYRmVkZXJhbCBDb21tb24gUG9s\n"
			+ "aWN5IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2HX7NRY0WkG/\n"
			+ "Wq9cMAQUHK14RLXqJup1YcfNNnn4fNi9KVFmWSHjeavUeL6wLbCh1bI1FiPQzB6+\n"
			+ "Duir3MPJ1hLXp3JoGDG4FyKyPn66CG3G/dFYLGmgA/Aqo/Y/ISU937cyxY4nsyOl\n"
			+ "4FKzXZbpsLjFxZ+7xaBugkC7xScFNknWJidpDDSPzyd6KgqjQV+NHQOGgxXgVcHF\n"
			+ "mCye7Bpy3EjBPvmE0oSCwRvDdDa3ucc2Mnr4MrbQNq4iGDGMUHMhnv6DOzCIJOPp\n"
			+ "wX7e7ZjHH5IQip9bYi+dpLzVhW86/clTpyBLqtsgqyFOHQ1O5piF5asRR12dP8Qj\n"
			+ "wOMUBm7+nQIDAQABo4IBMDCCASwwDwYDVR0TAQH/BAUwAwEB/zCB6QYIKwYBBQUH\n"
			+ "AQsEgdwwgdkwPwYIKwYBBQUHMAWGM2h0dHA6Ly9odHRwLmZwa2kuZ292L2ZjcGNh\n"
			+ "L2NhQ2VydHNJc3N1ZWRCeWZjcGNhLnA3YzCBlQYIKwYBBQUHMAWGgYhsZGFwOi8v\n"
			+ "bGRhcC5mcGtpLmdvdi9jbj1GZWRlcmFsJTIwQ29tbW9uJTIwUG9saWN5JTIwQ0Es\n"
			+ "b3U9RlBLSSxvPVUuUy4lMjBHb3Zlcm5tZW50LGM9VVM/Y0FDZXJ0aWZpY2F0ZTti\n"
			+ "aW5hcnksY3Jvc3NDZXJ0aWZpY2F0ZVBhaXI7YmluYXJ5MA4GA1UdDwEB/wQEAwIB\n"
			+ "BjAdBgNVHQ4EFgQUrQx6dVzl85jEeZgOrCj9l/TnAvwwDQYJKoZIhvcNAQELBQAD\n"
			+ "ggEBAI9z2uF/gLGH9uwsz9GEYx728Yi3mvIRte9UrYpuGDco71wb5O9Qt2wmGCMi\n"
			+ "TR0mRyDpCZzicGJxqxHPkYnos/UqoEfAFMtOQsHdDA4b8Idb7OV316rgVNdF9IU+\n"
			+ "7LQd3nyKf1tNnJaK0KIyn9psMQz4pO9+c+iR3Ah6cFqgr2KBWfgAdKLI3VTKQVZH\n"
			+ "venAT+0g3eOlCd+uKML80cgX2BLHb94u6b2akfI8WpQukSKAiaGMWMyDeiYZdQKl\n"
			+ "Dn0KJnNR6obLB6jI/WNaNZvSr79PMUjBhHDbNXuaGQ/lj/RqDG8z2esccKIN47lQ\n"
			+ "A2EC/0rskqTcLe4qNJMHtyznGI8=\n"
			+ "-----END CERTIFICATE-----";
	

	public static synchronized CertificateCacheManager getInstance() {
		if (instance == null) {
			instance = new CertificateCacheManager(null);
		}
		instance.flattenCache();
		return instance;
	}

	private CertificateCacheManager(X509Certificate trustAnchor) {
		BasicConfigurator.configure();
		Logger.getRootLogger().setLevel(Level.INFO);
		LOG.info("Initializing Certificate Cache");
		/*
		 * Eventually we will use the trustAnchor that is submitted,
		 * but for now, we will load our own.
		 */
		BouncyCastleProvider bc = new BouncyCastleProvider();
		Security.addProvider(bc);

		try {
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			ByteArrayInputStream bais = new ByteArrayInputStream(COMMON_SHA2_PEM.getBytes());
			trustAnchor = (X509Certificate) cf.generateCertificate(bais);
			this.cache = new CertificateCache(trustAnchor);
			/*
			 * Since this is our Trust Anchor, we are going to set the
			 * issuer CertID to match the subject
			 */
			this.cache.setSubjectCertId(ValidationUtils.getCertIdentifier(this.cache.getCertificate(), this.cache.getCertificate()).toASN1Object());
			
			this.cache.setIssuerCertId(this.cache.getSubjectCertId());
			/*
			 * Now that we are just creating the cache, lets perform
			 * issuedByThisCA discovery to find all of our possible subjects
			 * and then add them to the cache.  Recursively perform this
			 * discovery until there are no more to be discovered.
			 */
			this.issuedByThisCaDiscovery();
			/*
			 * Flatten the cache. NOTE: Any updates to the Cache
			 * SHALL require the flattend cache representation
			 * to be updated.
			 */
			this.flattenCache();
			/*
			 * Now, discover and download all of the CRLs for the
			 * certificates in our cache.
			 */
			this.getCRLs();
			/*
			 * Start path building with each of the certificates
			 * and use the CRLs in the path.  We will cache all
			 * of the valid policies from each CA and rely on them
			 * for cached validation.
			 * 
			 * TODO: PKIXValidation for every cert in the cache!
			 */
			this.validateCache();
			this.flattenCache();
			/*
			 * Then perform reverse discovery all the way back to the Trust
			 * Anchor from each of the leaves.
			 */
			//TODO: Reverse Discovery
			/*
			 * For any new certificates, this will look familiar...
			 * 
			 * Get CRLS and OCSP...
			 * Check for revocation...
			 * Prune...
			 */
			/*
			 * CACHE IS BUILT!
			 * 
			 * Now, schedule tasks to keep the cache up-to-date.
			 * But wait!, that's not all!
			 * 
			 * When we encounter a client cert where the immediate
			 * issuer is not in the path, do a reverse chase, and...
			 * 
			 * Get CRLS and OCSP...
			 * Check for revocation...
			 * Prune...
			 * 
			 * THEN, we can provide a response back to the client.
			 */
		} catch(CertificateException e) {
			LOG.fatal("Problem with Trust Anchor.", e);
		} catch (ValidationException e) {
			LOG.fatal("Problem with Trust Anchor.", e);
		} catch (PKIXValidatorException e) {
			LOG.fatal("Error validating cache.", e);
		}
	}
	
	public synchronized void issuedByThisCaDiscovery() {
		LOG.info("Performing issuedByThisCA Discovery");
		/*
		 * TODO: Add: cache.reset();
		 */
		this.cache = ValidationUtils.issuedByThisCADiscovery(this.cache, null);
	}
	
	public synchronized CertificateCache getCache() {
		return this.cache;
	}

	private synchronized void flattenCache() {
		this.fCache = null;
		this.fCache = this.cache.getFlattentedCache();
	}


	private synchronized void validateCache() throws PKIXValidatorException {
		CertificateCache oldCache = this.cache;
		this.cache = null;
		this.cache = ValidationUtils.getValidatedCache(oldCache);
	}

	public synchronized void putfCacheEntry(CertificateCache ce) {
		this.fCache.put(ce.getSubjectCertId(), ce);
	}
	
	public synchronized Collection<CertificateCache> getAllIntermediateEntries() {
		this.flattenCache();
		return this.fCache.values();
	}

	public synchronized CertificateCache getSigner(CertID subject) throws CertificateCacheException {
		if (subject.equals(this.cache.getSubjectCertId())) {
			//Clone the Trust Anchor Entry
			//CertificateCache clone = new CertificateCache(this.cache.getCertificate());
			//clone.setIssuerCertId(cache.getIssuerCertId());
			//clone.setSubjectCertId(cache.getSubjectCertId());
			//return clone;
			return null;
		} else 
		if (this.fCache.containsKey(subject)) {
			return this.fCache.get(subject);
		} else {
			throw new CertificateCacheException("Cache Entry Not Found");
		}
	}
	
	public synchronized Iterator<CertificateCache> getSignerPath(CertID subject) throws CertificateCacheException {
		ArrayList<CertificateCache> path = new ArrayList<CertificateCache>();
		if (subject.equals(this.cache.getSubjectCertId())) {
			return null;
		}
		/*
		 * Get the subject
		 */
		CertificateCache currentCc = getSigner(subject);
		path.add(currentCc);
		/*
		 * Get all intermediates to the trust anchor
		 */
		while (currentCc != null && !currentCc.getCertificate().equals(this.cache.getCertificate())) {
			currentCc = getSigner(currentCc.getIssuerCertId());
			if (currentCc != null) {
				path.add(currentCc);
			}
		}
		return path.iterator();
	}
	
	public synchronized Iterator<CertificateCache> getFlattenedCache() {
		return fCache.values().iterator();
	}
	
	private synchronized void getCRLs() {
		ValidationUtils.getCRLs(this.fCache);
	}
	
	
}
