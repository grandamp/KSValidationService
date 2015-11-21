package org.keysupport.pki.validation;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.keysupport.pki.asn1.NameConstraints;

public class PKIXValidator {

	private static final Log LOG = LogFactory.getLog(PKIXValidator.class);

	/*
	 * We want to use this class to:
	 * 
	 * Build a certificate path using PKIX (RFC 5280)
	 * Use the certificate cache for the validation inputs.  Specifically:
	 * 	-Trust Anchor
	 * 	-Intermediates
	 * 	-CRL Cache
	 * 
	 * This class "Should" be a singleton, based on the latest cache. (or, the constants should be singletons)
	 * Rather, there should be a PKIXValidatorManager singleton that manages the items we need as singletons, and then provides us with
	 * PKIXValidator instances through a getValidator method.
	 * 
	 * I.e., PKIXValidatorManager pkixManager = PKIXValidatorManager.getInstance();
	 *       PKIXValidator validator = PKIXValidatorManager.getValidator();
	 * 
	 * -When there is a change to the cache, this class instance should be set to null, and then re-initialized.
	 * 
	 * It will be used to validate the cache and internal intermediates (using cached CRLs)
	 * It will be used to validate ee certs using the CRL checked cache, and an OCSP validation on the EE cert.
	 * 
	 * The constants need to be the cache objects.
	 * The instance needs to be initialized using system properties for validation parameters.
	 * There are cache parameters.
	 * There are request, or "policy" identified parameters.
	 * 
	 * The parameters to be defined are:
	 * 
	 * initialPolicySet
	 * validityDate
	 * requreExplicitPolicy
	 * inhibitPolicyMapping
	 * inhibitAnyPolcy
	 * policyQualifiersRejected
	 * maxPathLength
	 * 
	 * We need to establish rules for the cache, like:
	 * 
	 * Include reverse cross certificates
	 *   -I.e., they may not have any value if validating to the trust anchor only.
	 *   -at least one set of policies must map, more are fine
	 *   -move entries with stale CRLs to reject cache (perhaps allow OCSP as a backup)
	 *   
	 * Does not really belong here, but we also need to establish rules for the AIA chase.
	 * 
	 * -Max num bytes for EE certificates;
	 * -Max AIA artifacts & bytes encountered to resolve an EE's path to an issuing CA;
	 * -Max CRL bytes for CRLs;
	 * 
	 * 
	 */
	
	private TrustAnchor trustAnchor = null;
	private CertStore intermediateStore = null;
	private CertStore crlStore = null;

	/*
	 * The following are needed for:
	 * 
	 * - PKIXBuilderParameters
	 * - PKIXParameters
	 * 
	 * They will be initialized by application properties
	 * when this object is created, but may be altered
	 * after this object is created based on the validation
	 * use case.
	 * 
	 * The following option is not set through a global:
	 * 
	 * PKIXParameters.setRevocationEnabled(boolean val)
	 * 
	 * It is entirely based on the use case of validating
	 * an end entity certificate on top of a revocation checked
	 * cache.  Yet, an OCSP check will occur on the end entity
	 * certificate.
	 */
	private NameConstraints nameConstraints = null;
	private Set<String> initialPolicySet = new HashSet<String>();
	private Date validityDate = null;
	private boolean requreExplicitPolicy = true;
	private boolean inhibitPolicyMapping = false;
	private boolean inhibitAnyPolcy = true;
	private boolean policyQualifiersRejected = false;
	private int maxPathLength = 20;
	private String sigProvider = null;

	@SuppressWarnings("unused")
	private PKIXValidator() {
		/*
		 * Hidden Constructor
		 */
	}

	protected PKIXValidator(TrustAnchor trustAnchor, CertStore intermediateStore, CertStore crlStore) {
		this.trustAnchor = trustAnchor;
		this.intermediateStore = intermediateStore;
		this.crlStore = crlStore;
	}

	/**
	 * @return the trustAnchor
	 */
	public TrustAnchor getTrustAnchor() {
		return trustAnchor;
	}

	/**
	 * @return the intermediateStore
	 */
	public CertStore getIntermediateStore() {
		return intermediateStore;
	}

	/**
	 * @return the crlStore
	 */
	public CertStore getCrlStore() {
		return crlStore;
	}

	/**
	 * @return the initialPolicySet
	 */
	public Set<String> getInitialPolicySet() {
		return initialPolicySet;
	}

	/**
	 * @param initialPolicySet the initialPolicySet to set
	 */
	public void setInitialPolicySet(Set<String> initialPolicySet) {
		this.initialPolicySet = initialPolicySet;
	}

	/**
	 * @param initialPolicySet the initialPolicySet to set
	 */
	public void clearInitialPolicySet() {
		this.initialPolicySet = new HashSet<String>();
	}

	/**
	 * @param initialPolicySet the initialPolicySet to set
	 */
	public void addInitialPolicy(String initialPolicy) {
		this.initialPolicySet.add(initialPolicy);
	}

	/**
	 * @return the validityDate
	 */
	public Date getValidityDate() {
		return validityDate;
	}

	/**
	 * @param validityDate the validityDate to set
	 */
	public void setValidityDate(Date validityDate) {
		this.validityDate = validityDate;
	}

	/**
	 * @return the requreExplicitPolicy
	 */
	public boolean isRequreExplicitPolicy() {
		return requreExplicitPolicy;
	}

	/**
	 * @param requreExplicitPolicy the requreExplicitPolicy to set
	 */
	public void setRequreExplicitPolicy(boolean requreExplicitPolicy) {
		this.requreExplicitPolicy = requreExplicitPolicy;
	}

	/**
	 * @return the inhibitPolicyMapping
	 */
	public boolean isInhibitPolicyMapping() {
		return inhibitPolicyMapping;
	}

	/**
	 * @param inhibitPolicyMapping the inhibitPolicyMapping to set
	 */
	public void setInhibitPolicyMapping(boolean inhibitPolicyMapping) {
		this.inhibitPolicyMapping = inhibitPolicyMapping;
	}

	/**
	 * @return the inhibitAnyPolcy
	 */
	public boolean isInhibitAnyPolcy() {
		return inhibitAnyPolcy;
	}

	/**
	 * @param inhibitAnyPolcy the inhibitAnyPolcy to set
	 */
	public void setInhibitAnyPolcy(boolean inhibitAnyPolcy) {
		this.inhibitAnyPolcy = inhibitAnyPolcy;
	}

	/**
	 * @return the policyQualifiersRejected
	 */
	public boolean isPolicyQualifiersRejected() {
		return policyQualifiersRejected;
	}

	/**
	 * @param policyQualifiersRejected the policyQualifiersRejected to set
	 */
	public void setPolicyQualifiersRejected(boolean policyQualifiersRejected) {
		this.policyQualifiersRejected = policyQualifiersRejected;
	}

	/**
	 * @return the maxPathLength
	 */
	public int getMaxPathLength() {
		return maxPathLength;
	}

	/**
	 * @param maxPathLength the maxPathLength to set
	 */
	public void setMaxPathLength(int maxPathLength) {
		this.maxPathLength = maxPathLength;
	}

	/**
	 * @return the sigProvider
	 */
	public String getSigProvider() {
		return sigProvider;
	}

	/**
	 * @param sigProvider the sigProvider to set
	 */
	public void setSigProvider(String sigProvider) {
		this.sigProvider = sigProvider;
	}

	/**
	 * @return the nameConstraints
	 */
	public NameConstraints getNameConstraints() {
		return nameConstraints;
	}

	/**
	 * @param nameConstraints the nameConstraints to set
	 * @throws PKIXValidatorException 
	 */
	public void setNameConstraints(NameConstraints nameConstraints) throws PKIXValidatorException {
		this.nameConstraints = nameConstraints;
		if (this.nameConstraints != null) {
			X509Certificate trustAnchorCert = this.trustAnchor.getTrustedCert();
			byte[] nConsBa = null;
			try {
				nConsBa = this.nameConstraints.getEncoded();
			} catch (IOException e) {
				throw new PKIXValidatorException("Unable to decode NameConstraints.", e);
			}
			if (nConsBa != null) {
				this.trustAnchor = new TrustAnchor(trustAnchorCert, nConsBa);
			}
		}
	}

	/**
	 * 
	 * This is the typical way, but we may not use it. We will have another method
	 * called getPaths, which return an array of CertPath showing all valid paths
	 * based on signing.  Then we can use a PKIX validator to validate each of the
	 * paths.
	 * 
	 * This one is good for validation of the cache to get the policy nodes.
	 * 
	 * @param cert
	 * @param checkRevocation
	 * @return
	 * @throws PKIXValidatorException
	 */
	public PKIXCertPathBuilderResult discoverPath(X509Certificate cert, boolean checkRevocation) throws PKIXValidatorException {
		/*
		 * Create our selector using the submitted certificate.
		 */
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(cert);
		List<X509Certificate> inputCerts = new ArrayList<X509Certificate>();
		inputCerts.add(this.trustAnchor.getTrustedCert());
		inputCerts.add(cert);

		/*
		 * Code segment used for path validation, not discovery
		 */

		//CertStoreParameters cparam = new CollectionCertStoreParameters(inputCerts);
		//CertStore cstore = null;
		//try {
		//	//cstore = CertStore.getInstance("Collection", cparam);
		//} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
		//	throw new PKIXValidatorException("Error creating initial certificate store", e);
		//}

		PKIXBuilderParameters params = null;
		try {
			params = new PKIXBuilderParameters(
					Collections.singleton(this.trustAnchor), selector);
		} catch (InvalidAlgorithmParameterException e) {
			throw new PKIXValidatorException("Error creating PKIX parameters", e);
		}
		
		/*
		 * Set the params from our globals
		 */
		params.setRevocationEnabled(checkRevocation);
		if (this.initialPolicySet != null && !this.initialPolicySet.isEmpty()) {
			params.setInitialPolicies(this.initialPolicySet);
		}
		if (this.validityDate != null) {
			params.setDate(this.validityDate);
		}
		params.setExplicitPolicyRequired(this.requreExplicitPolicy);
		params.setPolicyMappingInhibited(this.inhibitPolicyMapping);
		params.setAnyPolicyInhibited(this.inhibitAnyPolcy);
		params.setPolicyQualifiersRejected(this.policyQualifiersRejected);
		params.setMaxPathLength(this.maxPathLength);
		params.setSigProvider(this.sigProvider);

		params.addCertStore(this.intermediateStore);
		params.addCertStore(this.crlStore);
		LOG.debug("Parameters:\n" + params.toString());
		LOG.debug("--- BEGIN PATH DISCOVERY ---");
		CertPathBuilder cpb = null;
		try {
			cpb = CertPathBuilder.getInstance("PKIX");
		} catch (NoSuchAlgorithmException e) {
			throw new PKIXValidatorException("Error creating PKIX Path Builder Instance", e);
		}
		LOG.info("Path Builder Provider: "
				+ cpb.getProvider().toString());

		PKIXCertPathBuilderResult result = null;
		try {
			result = (PKIXCertPathBuilderResult)cpb.build(params);
		} catch (CertPathBuilderException e) {
			throw new PKIXValidatorException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new PKIXValidatorException(e);
		}
		/*
		 * Return the constructed path.
		 */
		return result;
	}

	public PKIXCertPathValidatorResult validatePath(X509Certificate cert, CertPath certPath, boolean checkRevocation) throws PKIXValidatorException {
		/*
		 * Create our selector using the submitted certificate.
		 */
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(cert);
		
//		byte[] certAki = null;
//		certAki = ValidationUtils.getAssertedAKI(cert);
//		if (certAki != null) {
//			SubjectKeyIdentifier caSki = null;
//			ASN1OctetString ki = new DEROctetString(certAki);
//			try {
//				caSki = SubjectKeyIdentifier.getInstance(ki);
//				if (caSki != null) {
//					System.out.println("ADDING SKI: " + DataUtil.byteArrayToString(caSki.getEncoded()));
//					selector.setSubjectKeyIdentifier(caSki.getEncoded());
//				}
//			} catch (IOException e) {
//				//Swallow
//			}
//		}
		
		
		List<X509Certificate> inputCerts = new ArrayList<X509Certificate>();
		inputCerts.add(this.trustAnchor.getTrustedCert());
		inputCerts.add(cert);

		/*
		 * Code segment used for path validation, not discovery
		 */

		//CertStoreParameters cparam = new CollectionCertStoreParameters(inputCerts);
		//CertStore cstore = null;
		//try {
		//	//cstore = CertStore.getInstance("Collection", cparam);
		//} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
		//	throw new PKIXValidatorException("Error creating initial certificate store", e);
		//}
		PKIXBuilderParameters params = null;
		try {
			params = new PKIXBuilderParameters(
					Collections.singleton(this.trustAnchor), selector);
		} catch (InvalidAlgorithmParameterException e) {
			throw new PKIXValidatorException("Error creating PKIX parameters", e);
		}
		
		/*
		 * Set the params from our globals
		 */
		params.setRevocationEnabled(checkRevocation);
		if (this.initialPolicySet != null && !this.initialPolicySet.isEmpty()) {
			params.setInitialPolicies(this.initialPolicySet);
		}
		if (this.validityDate != null) {
			params.setDate(this.validityDate);
		}
		params.setExplicitPolicyRequired(this.requreExplicitPolicy);
		params.setPolicyMappingInhibited(this.inhibitPolicyMapping);
		params.setAnyPolicyInhibited(this.inhibitAnyPolcy);
		params.setPolicyQualifiersRejected(this.policyQualifiersRejected);
		params.setMaxPathLength(this.maxPathLength);
		params.setSigProvider(this.sigProvider);

		params.addCertStore(this.intermediateStore);
		params.addCertStore(this.crlStore);
		LOG.debug("Parameters:\n" + params.toString());
		LOG.debug("--- BEGIN PATH VALIDATION ---");

		CertPathValidator cpv;
		try {
			cpv = CertPathValidator.getInstance("PKIX");
		} catch (NoSuchAlgorithmException e) {
			throw new PKIXValidatorException("Error creating PKIX Path Validator Instance", e);
		}
		PKIXCertPathValidatorResult pvr;
		try {
			pvr = (PKIXCertPathValidatorResult) cpv
					.validate(certPath, params);
		} catch (CertPathValidatorException e) {
			throw new PKIXValidatorException(e.getReason().toString(), e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new PKIXValidatorException(e);
		}
		LOG.info(pvr);
		LOG.debug("--- END PATH VALIDATION ---");
		return pvr;
	}

}
