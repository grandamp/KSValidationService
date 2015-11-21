package org.keysupport.pki.validation;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.keysupport.pki.validation.cache.CRLCacheManager;
import org.keysupport.pki.validation.cache.CertificateCache;
import org.keysupport.pki.validation.cache.CertificateCacheException;
import org.keysupport.pki.validation.cache.CertificateCacheManager;

public class PKIXValidatorManager {

	private volatile static PKIXValidatorManager instance = null;
	private static final Log LOG = LogFactory.getLog(PKIXValidatorManager.class);
	private CertificateCacheManager certManager = null;
	private CRLCacheManager crlManager = null;
	private static TrustAnchor trustAnchor = null;
	
	private static CertStore intermediateStore = null;
	private static CertStore crlStore = null;

	public static synchronized PKIXValidatorManager getInstance() throws PKIXValidatorException {
		if (instance == null) {
			instance = new PKIXValidatorManager();
		}
		return instance;
	}

	private PKIXValidatorManager() throws PKIXValidatorException {
		LOG.info("Initializing PKIX Validator Manager");
		certManager = CertificateCacheManager.getInstance();
		crlManager = CRLCacheManager.getInstance();
		/*
		 * Get the trust anchor
		 */
		X509Certificate trustAnchorCert = certManager.getCache().getCertificate();
		trustAnchor = new TrustAnchor(trustAnchorCert, null);
		if (trustAnchor == null) {
			LOG.fatal("Failed to initialize Trust Anchor");
			throw new PKIXValidatorException("Failed to initialize Trust Anchor");
		}
		/*
		 * Get intermediates into a CertStore
		 */
		ArrayList<X509Certificate> iCertList = new ArrayList<X509Certificate>();
		Collection<CertificateCache> it = certManager.getAllIntermediateEntries();
		for (CertificateCache entry: it) {
			iCertList.add(entry.getCertificate());
		}
		CertStoreParameters intParams = new CollectionCertStoreParameters(iCertList);
		try {
			intermediateStore = CertStore.getInstance("Collection", intParams);
		} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
			LOG.fatal("Failed to initialize Intermediate Store: " + e.getMessage());
			throw new PKIXValidatorException("Failed to initialize Intermediate Store", e);
		}
		/*
		 * Get CRLs into a store
		 */
		Collection<X509CRL> crlCol = crlManager.getCRLCache().getCRLs();
		CertStoreParameters crls = new CollectionCertStoreParameters(crlCol);
		try {
			crlStore = CertStore.getInstance("Collection", crls);
		} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
			LOG.fatal("Failed to initialize CRL Store: " + e.getMessage());
			throw new PKIXValidatorException("Failed to initialize Intermediate Store", e);
		}
	}

	public synchronized PKIXValidator getPKIXValidator() throws PKIXValidatorException {
		/*
		 * Render default NameConstraints from properties,
		 * and we will use a setter to recreate.  We will
		 * use null NameConstraints to create the initial object.
		 */
		PKIXValidator pVdr = new PKIXValidator(trustAnchor, intermediateStore, crlStore);
		/*
		 * TODO:  Initialize the PKIXValidator with the defaults
		 * from the properties. Setting hard coded defaults for now
		 * based on defaults in the PKIXValidator class.
		 * 
		 * These will effect the internal validation of the cache,
		 * while the values will be changed for end entity certificate
		 * validation.
		 */
		
		/*
		 * The following logic is reserved for future use
		 */
		//GeneralSubtree[] permitted = null; 
		//GeneralSubtree[] excluded = null;
		//NameConstraints nameConstraints = new NameConstraints(permitted, excluded);
		//if (nameConstraints != null) {
		//	pVdr.setNameConstraints(nameConstraints);
		//}

		Set<String> initialPolicySet = new HashSet<String>();
		pVdr.setInitialPolicySet(initialPolicySet);
		
		boolean requreExplicitPolicy = true;
		pVdr.setRequreExplicitPolicy(requreExplicitPolicy);
		
		boolean inhibitPolicyMapping = false;
		pVdr.setInhibitPolicyMapping(inhibitPolicyMapping);
		
		boolean inhibitAnyPolcy = true;
		pVdr.setInhibitAnyPolcy(inhibitAnyPolcy);

		boolean policyQualifiersRejected = false;
		pVdr.setPolicyQualifiersRejected(policyQualifiersRejected);
		
		int maxPathLength = 20;
		pVdr.setMaxPathLength(maxPathLength);
		
		String sigProvider = null;
		pVdr.setSigProvider(sigProvider);

		return pVdr;
	}

	public synchronized void refreshStoresFromCache() throws PKIXValidatorException {
		instance = null;
		instance = new PKIXValidatorManager();
	}

	/*
	 * Looks like we need to return an array of path builder results vs. simple certpaths:
	 * 
	 * PKIXCertPathBuilderResult(CertPath certPath, TrustAnchor trustAnchor, PolicyNode policyTree, PublicKey subjectPublicKey)
	 */
	public CertPath[] getAllPaths(X509Certificate cert) {
		Set<CertPath> paths = new HashSet<CertPath>();
		
		Collection<CertificateCache> allEntries = certManager.getAllIntermediateEntries();
		for (CertificateCache entry: allEntries) {
			if (entry.isSignerOf(cert)) {
				List<X509Certificate> setPath = new ArrayList<X509Certificate>();
				setPath.add(cert);
				Iterator<CertificateCache> pathEntries = null;
				try {
					pathEntries = certManager.getSignerPath(entry.getSubjectCertId());
				} catch (CertificateCacheException e) {
					LOG.fatal("Problem getting certificate path", e);
					/*
					 * Move on to the next one.  This is
					 * not likely to occur.
					 */
					break;
				}
				while (pathEntries != null && pathEntries.hasNext()) {
					CertificateCache ccpEntry = pathEntries.next();
					setPath.add(ccpEntry.getCertificate());
				}
				/*
				 * Now to create a CertPath with our set of certificates
				 */
				CertPath currentPath = null;
				try {
					CertificateFactory cf = CertificateFactory.getInstance("X509");
					currentPath = cf.generateCertPath(setPath);
				} catch (CertificateException e) {
					LOG.fatal("Problem getting certificate path", e);
				}
				if (currentPath != null) {
					paths.add(currentPath);
				}
			}
		}
		
		return paths.toArray(new CertPath[paths.size()]);
	}

}
