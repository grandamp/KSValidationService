package org.keysupport.pki.validation;

import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.keysupport.httpclient.HttpClient;
import org.keysupport.httpclient.HttpClientException;
import org.keysupport.httpclient.PkiUri;
import org.keysupport.pki.asn1.SubjectInformationAccess;
import org.keysupport.pki.validation.cache.CRLCacheManager;
import org.keysupport.pki.validation.cache.CertificateCache;
import org.keysupport.pki.validation.cache.DataUtil;
import org.keysupport.pki.validation.cache.RejectedCertCacheManager;
import org.keysupport.pki.validation.cache.URICacheEntry;
import org.keysupport.pki.validation.cache.UriCacheManager;

public class ValidationUtils {

	private static final Log LOG = LogFactory.getLog(ValidationUtils.class);

	private ValidationUtils() {
		/*
		 * Hidden Constructor.  All utility methods must be static.
		 */
	}
	
	public static boolean isCa(X509Certificate caCert) {
		if (caCert.getBasicConstraints()>-1) {
			return true;
		} else {
			return false;
		}
	}

	public static byte[][] getCalculatedSKIs(X509Certificate caCert) {
		byte[][] skis = new byte[2][];
		skis[0] = getPkixExOneSki(caCert.getPublicKey());
		skis[1] = getPkixExTwoSki(caCert.getPublicKey());
		return skis;
	}

	/**
	 * This method is used to calculate key identifiers. 
	 * Both RFC 3280 and RFC 5280 provide examples on
	 * key identifier generation.
	 */
	private static byte[] sha1Sum(byte[] ba) {
		byte[] digest = null;
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
			md.update(ba);
			digest = md.digest();
		} catch (NoSuchAlgorithmException e) {
			/*
			 * Swallowing because all JCE providers require
			 * SHA-1 support
			 */
		}
		return digest;
	}
	
	/**
	 * Based on BouncyCastle Code.
	 * 
	 * Return a RFC 3280/5280 example 1 key identifier. As in:
	 * <pre>
	 * (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
	 * value of the BIT STRING subjectPublicKey (excluding the tag,
	 * length, and number of unused bits).
	 * </pre>
	 * @param key the public key of the certificate.
	 * @return the key identifier.
	 */
	public static byte[] getPkixExOneSki(PublicKey key) {
		return sha1Sum(key.getEncoded());
	}

	/**
	 * Based on BouncyCastle Code.
	 * 
	 * Return a RFC 3280/5280 example 2 key identifier. As in:
	 * <pre>
	 * (2) The keyIdentifier is composed of a four bit type field with
	 * the value 0100 followed by the least significant 60 bits of the
	 * SHA-1 hash of the value of the BIT STRING subjectPublicKey.
	 * </pre>
	 * @param key the public key of the certificate.
	 * @return the key identifier.
	 */
	public static byte[] getPkixExTwoSki(PublicKey key) {
		byte[] dig = sha1Sum(key.getEncoded());
		byte[] id = new byte[8];
		System.arraycopy(dig, dig.length - 8, id, 0, id.length);
		id[0] &= 0x0f;
		id[0] |= 0x40;
		return id;
	}

	private static Extensions getExtensions(X509Certificate cert) {
		Set<String> critExt = cert.getCriticalExtensionOIDs();
		Set<String> nonCritExt = cert.getNonCriticalExtensionOIDs();
		Set<Extension> extensions = new HashSet<Extension>();
		for (String oidStr: critExt) {
			ASN1ObjectIdentifier extnId = new ASN1ObjectIdentifier(oidStr);
			byte[] extBytes = cert.getExtensionValue(oidStr);
			extensions.add(new Extension(extnId, true, ASN1OctetString.getInstance(extBytes)));
		}
		for (String oidStr: nonCritExt) {
			ASN1ObjectIdentifier extnId = new ASN1ObjectIdentifier(oidStr);
			byte[] extBytes = cert.getExtensionValue(oidStr);
			extensions.add(new Extension(extnId, false, ASN1OctetString.getInstance(extBytes)));
		}
		Extension[] extArr = new Extension[critExt.size() + nonCritExt.size()];
		return new Extensions(extensions.toArray(extArr));
	}
	
	public static PkiUri[] getHttpInfoUris(X509Certificate cert) {
		return getInfoUris(cert, URICacheEntry.HTTP);
	}

	public static PkiUri[] getLdapInfoUris(X509Certificate cert) {
		return getInfoUris(cert, URICacheEntry.LDAP);
	}

	private static PkiUri[] getInfoUris(X509Certificate cert, String protocol) {
		PkiUri[] siaUri = getSiaUris(cert, protocol);
		PkiUri[] aiaUri = getAiaUris(cert, protocol, AccessDescription.id_ad_caIssuers);
		PkiUri[] infoUris = new PkiUri[siaUri.length + aiaUri.length];
		System.arraycopy(siaUri, 0, infoUris, 0, siaUri.length);
		System.arraycopy(aiaUri, 0, infoUris, siaUri.length, aiaUri.length);
		return infoUris;
	}

	public static PkiUri[] getHttpSiaUris(X509Certificate cert) {
		return getSiaUris(cert, URICacheEntry.HTTP);
	}

	public static PkiUri[] getLdapSiaUris(X509Certificate cert) {
		return getSiaUris(cert, URICacheEntry.LDAP);
	}

	private static PkiUri[] getSiaUris(X509Certificate cert, String protocol) {
		Set<PkiUri> uris = new HashSet<PkiUri>();
		int reason = PkiUri.CERTSONLYCMS;
		int subReason = PkiUri.SIA;

		Extensions exts = getExtensions(cert);
		AccessDescription[] ads = null;
		/*
		 * No SIA in BC, so we created our own
		 */
		Extension siaExt = null;
		if ((siaExt = exts.getExtension(Extension.subjectInfoAccess)) != null) {
			SubjectInformationAccess sia = SubjectInformationAccess.getInstance((ASN1Sequence)siaExt.getParsedValue());
			ads = sia.getAccessDescriptions();
			for (AccessDescription ad: ads) {
				if (ad.getAccessMethod().equals(SubjectInformationAccess.id_ad_caRepository)) {
					GeneralName al = ad.getAccessLocation();
					if (al.getTagNo() == GeneralName.uniformResourceIdentifier) {
						URI thisURI = null;
						try {
							thisURI = new URI(al.getName().toString());
						} catch (URISyntaxException e) {
							LOG.fatal("Error parsing URI from certificate: " + e.getMessage(), e);
							/*
							 * We will swallow this exception for now,
							 * and simply not add it if thisURI is null
							 */
						}
						if (thisURI != null && thisURI.getScheme().toLowerCase().startsWith(protocol)) {
							uris.add(new PkiUri(thisURI, reason, subReason));
						}
					}
				}
			}
		}
		return uris.toArray(new PkiUri[uris.size()]);
	}

	public static PkiUri[] getHttpCdpUris(X509Certificate cert) {
		return getCdpUris(cert, URICacheEntry.HTTP);
	}

	public static PkiUri[] getLdapCdpUris(X509Certificate cert) {
		return getCdpUris(cert, URICacheEntry.LDAP);
	}

	private static PkiUri[] getCdpUris(X509Certificate cert, String protocol) {
		Set<PkiUri> uris = new HashSet<PkiUri>();
		int reason = PkiUri.CDP;
		int subReason = PkiUri.NOREASON;
		
		Extensions exts = getExtensions(cert);
		DistributionPoint[] dps = null;
		Extension cdpExt = null;
		if ((cdpExt = exts.getExtension(Extension.cRLDistributionPoints)) != null) {
			CRLDistPoint cdp = CRLDistPoint.getInstance((ASN1Sequence)cdpExt.getParsedValue());
			dps = cdp.getDistributionPoints();
			for (DistributionPoint dp: dps) {
				GeneralNames gNames = null;
				if ((gNames = dp.getCRLIssuer()) != null) {
					ReasonFlags reasons = null;
					if ((reasons = dp.getReasons()) != null) {
						LOG.info("Certificate contains CDP URI with ReasonFlags.");
						subReason = reasons.intValue();
					}
					GeneralName[] gns = gNames.getNames();
					for (GeneralName gn: gns) {
						if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
							URI thisURI = null;
							try {
								thisURI = new URI(gn.getName().toString());
							} catch (URISyntaxException e) {
								LOG.fatal("Error parsing URI from certificate: " + e.getMessage(), e);
								/*
								 * We will swallow this exception for now,
								 * and simply not add it is thisURI is null
								 */
							}
							if (thisURI != null && thisURI.getScheme().toLowerCase().startsWith(protocol)) {
								uris.add(new PkiUri(thisURI, reason, subReason));
							}
						}
					}
				}
				DistributionPointName dpn = null;
				if ((dpn = dp.getDistributionPoint()) != null) {
					if (dpn.getType() == DistributionPointName.FULL_NAME) {
						GeneralName[] gns = GeneralNames.getInstance(dpn.getName()).getNames();
						for (GeneralName gn: gns) {
							if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
								URI thisURI = null;
								try {
									thisURI = new URI(gn.getName().toString());
								} catch (URISyntaxException e) {
									LOG.fatal("Error parsing URI from certificate: " + e.getMessage(), e);
									/*
									 * We will swallow this exception for now,
									 * and simply not add it is thisURI is null
									 */
								}
								if (thisURI != null && thisURI.getScheme().toLowerCase().startsWith(protocol)) {
									uris.add(new PkiUri(thisURI, reason, subReason));
								}
							}
						}
					}
				}
			}
		}
		return uris.toArray(new PkiUri[uris.size()]);
	}

	public static PkiUri[] getHttpAiaUris(X509Certificate cert) {
		return getAiaUris(cert, URICacheEntry.HTTP, AccessDescription.id_ad_caIssuers);
	}

	public static PkiUri[] getLdapAiaUris(X509Certificate cert) {
		return getAiaUris(cert, URICacheEntry.LDAP, AccessDescription.id_ad_caIssuers);
	}

	public static PkiUri[] getOcspUris(X509Certificate cert) {
		return getAiaUris(cert, URICacheEntry.HTTP, AccessDescription.id_ad_ocsp);
	}

	private static PkiUri[] getAiaUris(X509Certificate cert, String protocol, ASN1ObjectIdentifier accessMethod) {
		Set<PkiUri> uris = new HashSet<PkiUri>();
		int reason = PkiUri.NOREASON;
		int subReason = PkiUri.NOREASON;

		if (accessMethod.equals(AccessDescription.id_ad_ocsp)) {
			reason = PkiUri.OCSP;
		} else if (accessMethod.equals(AccessDescription.id_ad_caIssuers)) {
			reason = PkiUri.CERTSONLYCMS;
			subReason = PkiUri.AIA;
		}

		Extensions exts = getExtensions(cert);
		AccessDescription[] ads = null;
		Extension aiaExt = null;
		if ((aiaExt = exts.getExtension(Extension.authorityInfoAccess)) != null) {
			AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance((ASN1Sequence)aiaExt.getParsedValue());
			ads = aia.getAccessDescriptions();
			for (AccessDescription ad: ads) {
				if (ad.getAccessMethod().equals(accessMethod)) {
					GeneralName al = ad.getAccessLocation();
					if (al.getTagNo() == GeneralName.uniformResourceIdentifier) {
						URI thisURI = null;
						try {
							thisURI = new URI(al.getName().toString());
						} catch (URISyntaxException e) {
							/*
							 * We will swallow this exception for now,
							 * and simply not add it is thisURI is null
							 */
						}
						if (thisURI != null && thisURI.getScheme().toLowerCase().startsWith(protocol)) {
							uris.add(new PkiUri(thisURI, reason, subReason));
						}
					}
				}
			}
		}
		return uris.toArray(new PkiUri[uris.size()]);
	}

	public static CertificateID getCertIdentifier(X509Certificate issuer, X509Certificate subject) throws ValidationException {
		X509CertificateHolder caCert = null;
		try {
			caCert = new JcaX509CertificateHolder(issuer);
		} catch (CertificateEncodingException e) {
			throw new ValidationException(e);
		}
		DigestCalculatorProvider digCalcProv = null;
		try {
			digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
		} catch (OperatorCreationException e) {
			throw new ValidationException(e);
		}
		try {
			return new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), caCert, subject.getSerialNumber());
		} catch (OperatorCreationException e) {
			throw new ValidationException(e);
		} catch (OCSPException e) {
			throw new ValidationException(e);
		}
	}

	public static byte[] getAssertedSKI(X509Certificate caCert) {
		byte[] extBytes = null;
		caCert.getExtensionValue("2.5.29.14");
		if ((extBytes = caCert.getExtensionValue("2.5.29.14")) != null) {
			byte[] extOctetString = ASN1OctetString.getInstance(extBytes).getOctets();
			return SubjectKeyIdentifier.getInstance(extOctetString).getKeyIdentifier();
		} else {
			return null;
		}
	}

	//"2.5.29.35"
	public static byte[] getAssertedAKI(X509Certificate cert) {
		byte[] extBytes = null;
		if ((extBytes = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId())) != null) {
			byte[] extOctetString = ASN1OctetString.getInstance(extBytes).getOctets();
			return AuthorityKeyIdentifier.getInstance(extOctetString).getKeyIdentifier();
		} else {
			return null;
		}
	}

	/**
	 * The intent on the method name is to remove confusion on "forward" or "reverse" 
	 * discovery.  We will use the terminology for crossCertificatePair in ITU-T X.509 (2012):
	 * 
	 * "The term forward was used in previous editions for issuedToThisCA and the term reverse 
	 * was used in previous editions for issuedByThisCA".  In old terms, this is "reverse" 
	 * discovery since we are doing an SIA chase.
	 * 
	 * 
	 * @param certCache
	 * @return
	 */
	public static CertificateCache issuedByThisCADiscovery(CertificateCache certCache, Set<byte[]> currentPath) {
		/*
		 * We are going to build a set of SKIs so we
		 * can see all the keys in the path we are building.
		 * 
		 * We will use this as we discover new certificates to
		 * filter out any cross certificates that go in the
		 * wrong direction for our needs.
		 */
		Set<byte[]> forkedPath = new HashSet<byte[]>();
		if (currentPath != null) {
			forkedPath.addAll(currentPath);
		}
		/*
		 * Get the RejectedCertCacheManager instance so we can
		 * manage rejected certificates as we discover.
		 */
		RejectedCertCacheManager rejectManager = RejectedCertCacheManager.getInstance();
		/*
		 * Get the HTTP SIA URIs from the certificate in the
		 * certificate cache entry we are evaluating
		 */
		PkiUri[] siaUris = ValidationUtils.getHttpSiaUris(certCache.getCertificate());
		/*
		 * If there are HTTP SIA URIs, then process them,
		 * otherwise, return our certificate cache entry
		 * unmodified.
		 */
		HttpClient client = HttpClient.getInstance();
		if (siaUris != null && siaUris.length>0)
		for (PkiUri uri: siaUris) {
			UriCacheManager uriCm = UriCacheManager.getInstance();
			/*
			 * Check our URI cache to see if we
			 * have already fetched the data.  The
			 * URI cache will have a scheduler attached
			 * for periodic updates using a cache.refresh()
			 */
			if (uriCm.getUriCache().isInCache(uri)) {
				LOG.info("URI is in URI Cache, Skipping: " + uri.toString());
				break;
			}
			LOG.info("We have not seen this URI yet, Fetching: " + uri.toString());
			byte[] cmsCertsBa = null;
			/*
			 * NOTE:  If we catch an exception here on the first SIA URI, we
			 * are dead in the water for issuedByThisCA discovery.  TODO:  Add a timer and re-discover.
			 */
			try {
				cmsCertsBa = client.getRequest(uri);
			} catch (HttpClientException e) {
				LOG.fatal("Error getting during SIA chase: " + e.getMessage(), e);
			}
			if (cmsCertsBa != null) {
				CMSSignedData cms = null;
				try {
					cms = new CMSSignedData(cmsCertsBa);
				} catch (CMSException e) {
					LOG.fatal("Error parsing certs-only CMS message: " + e.getMessage(), e);
				}
				if (cms != null) {
					Store certStore = cms.getCertificates();
					@SuppressWarnings("unchecked")
					ArrayList<X509CertificateHolder> certC = (ArrayList<X509CertificateHolder>) certStore.getMatches(null);
					LOG.info("Discovered " + certC.size() + " certificates!");
					LOG.debug("certs-only message: " + DataUtil.byteArrayToString(cmsCertsBa));
					JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
					/*
					 * We need to loop through the certificates we find,
					 * and add them as children to the caller.
					 */
					for (X509CertificateHolder ch: certC) {
						LOG.info("Processing discovered cert: " + ch.getSubject().toString());
						X509Certificate thisCert = null;
						try {
							thisCert = converter.getCertificate(ch);
						} catch (CertificateException e) {
							LOG.fatal("Error getting X509Certificate from X509CertificateHolder: " + e.getMessage(), e);
						}
						/*
						 * Let's determine the SKI so we can evaluate if
						 * this is a certificate in the wrong direction
						 * below.
						 */
						byte[] childSKI = getAssertedSKI(thisCert);
						if (childSKI == null) {
							childSKI = getPkixExOneSki(thisCert.getPublicKey());
						}
						/*
						 * Make sure the certificate we are evaluating:
						 * -Is not null
						 * -Is a CA certificate
						 * -Is not the CA we are performing the discovery on
						 * -Is signed by the CA we are performing a discovery on
						 * -Is not expired
						 * 
						 * If the certificate does not meet the requirements
						 * above, place it in the rejected certificate cache.
						 */
						if (thisCert != null &&
								isCa(thisCert) &&
								thisCert != certCache.getCertificate() &&
								certCache.isSignerOf(thisCert) &&
								rejectManager.isAcceptableCA(thisCert, uri.toString()) &&
								rejectManager.isRightDirection(childSKI, thisCert, forkedPath, uri.toString())) {
							/*
							 * We are preparing to add this child to our
							 * cache, so we will add the child's SKI
							 * to the path.
							 */
							forkedPath.add(childSKI);
							/*
							 * Create a child CertCache Object,
							 * and add it to the parent certCache.
							 */
							CertificateCache childCertCache = new CertificateCache(thisCert);
							if (childCertCache != null) {
								CertID issuerCertId = certCache.getSubjectCertId();
								childCertCache.setIssuerCertId(issuerCertId);
								CertID subjectCertId = null;
								try {
									subjectCertId = ValidationUtils.getCertIdentifier(certCache.getCertificate(), childCertCache.getCertificate()).toASN1Object();
								} catch (ValidationException e) {
									LOG.fatal("Error generating CertID for child: " + e.getMessage(), e);
								}
								if (subjectCertId != null) {
									childCertCache.setSubjectCertId(subjectCertId);
								}
								//certManager.putfCacheEntry(childCertCache);
								childCertCache = issuedByThisCADiscovery(childCertCache, forkedPath);
								certCache.addSubject(childCertCache);
							}
						}
					}
				}
			}
		} else {
			/*
			 * No SIA!  Return our cacheEntry unmodified!
			 */
			LOG.info("Certificate does not contain SIA extension.  End of path?");
			return certCache;
		}
		return certCache;
	}

	public static String certToPem(final X509Certificate cert) throws ValidationException {
		try {
			StringWriter stringWriter = new StringWriter();
			PemWriter pemWriter = new PemWriter(stringWriter);
			pemWriter.writeObject(new PemObject("CERTIFICATE",
					cert.getEncoded()));
			pemWriter.flush();
			pemWriter.close();
			return stringWriter.toString();
		} catch (IOException e) {
			throw new ValidationException(
					"Conversion Failure: " + e.getMessage(), e);
		} catch (CertificateEncodingException e) {
			throw new ValidationException(
					"Conversion Failure: " + e.getMessage(), e);
		}
	}

	public static String getUrlSafeB64(byte[] arr) {
		return Base64.encodeBase64URLSafeString(arr);
	}
	
	public static byte[] decodeFromUrlSafeB64(String b64) {
		return Base64.decodeBase64(b64);
	}
	
	public static void getCRLs(ConcurrentHashMap<CertID, CertificateCache> fCache) {
		Iterator<CertificateCache> certs = fCache.values().iterator();
		CRLCacheManager crlManager = CRLCacheManager.getInstance();
		while (certs.hasNext()) {
			CertificateCache cert = certs.next();
			if (cert != null) {
				PkiUri[] httpCDP = cert.getHttpCdpUris();
				if (httpCDP != null && httpCDP.length > 0) {
					for (PkiUri uri: httpCDP) {
						try {
							crlManager.getCRL(uri);
						} catch (CRLException e) {
							LOG.fatal("Failed to obtain CRL: " + e.getMessage(), e);
							e.printStackTrace();
						}
					}
				}
			}
		}
	}
	
	public static CertificateCache pkixValidateChild(CertificateCache child) throws PKIXValidatorException {

		/*
		 * Get the RejectedCertCacheManager instance so we can
		 * manage rejected certificates as we discover.
		 */
		RejectedCertCacheManager rejectManager = RejectedCertCacheManager.getInstance();

		/*
		 * Get PKIXValidatorManager instance for CertificateCache
		 * entry validation.
		 */
		PKIXValidatorManager pkixManager = null;
		PKIXValidator validator = null;
		
		String pathError = null;
		try {
			pkixManager = PKIXValidatorManager.getInstance();
			validator = pkixManager.getPKIXValidator();
		} catch(PKIXValidatorException e) {
			throw new PKIXValidatorException("Error initializing PKIX Validation", e);
		}
		/*
		 * Do a simple clone of the child
		 */
		CertificateCache clone = new CertificateCache(child.getCertificate());
		clone.setIssuerCertId(child.getIssuerCertId());
		clone.setSubjectCertId(child.getSubjectCertId());
		clone.setPolicyTree(child.getPolicyTree());
		/*
		 * Save off the child's children.
		 */
		ArrayList<CertificateCache> children = child.getSubjects();
		
		/*
		 * TODO: Validate the child using PKIX with the server default
		 * PKIX settings.
		 */
		PKIXCertPathBuilderResult dResult = null;
		try {
			dResult =  validator.discoverPath(clone.getCertificate(), true);
		} catch(PKIXValidatorException e) {
			pathError = e.getCause().getMessage();
			LOG.info("Error building path: " + pathError);
		}

		 /* if there is a failure:
		 * 
		 *   -add the certificate to the rejected cache
		 *   -reset the validation manager
		 *      -rebuild the flattened cache? (or, the caller will do this)
		 *   -return null
		 */
		if (dResult == null) {
			rejectManager.putRejectedCertificate(clone.getCertificate(), pathError, "Pulled from Cache");
			validator = null;
			pkixManager = null;
			return null;
		}
		 /* if no failure
		 *   -proceed.
		 */
		clone.setPolicyTree(dResult.getPolicyTree());
		/*
		 * Add the children back to the child
		 */
		clone.setSubjects(children);
		/*
		 * For each policy in the policy map,
		 * place the policy in the child object
		 * through:  addValidPolicy(ASN1ObjectIdentifier validPolicy)
		 */
		/*
		 * Return the child object.
		 */
		return clone;
	}
	
	public static CertificateCache getValidatedCache(CertificateCache cache) throws PKIXValidatorException {
		
		/*
		 * There is no need to validate the root Cache entry, so we
		 * are going to dig right into rebuilding the cache children.
		 */
		CertificateCache validatedEntry = null;
		if (!cache.isSelfSigned()) {
			LOG.info("Validating cache entry for: " + cache.getCertificate().getSubjectX500Principal().getName());
			validatedEntry = pkixValidateChild(cache);
		} else {
			validatedEntry = cache;
		}
		if (validatedEntry != null) {
			ArrayList<CertificateCache> subjects = validatedEntry.getSubjects();
			if (subjects != null && subjects.size() > 0) {
				ArrayList<CertificateCache> validatedSubjects = new ArrayList<CertificateCache>();
				for (CertificateCache entry: subjects) {
					CertificateCache validatedChildEntry = null;
					validatedChildEntry = getValidatedCache(entry);
					if (validatedChildEntry != null) {
						validatedSubjects.add(validatedChildEntry);
					}
				}
				if (validatedSubjects.size() > 0) {
					validatedEntry.setSubjects(validatedSubjects);
				}
			}
		}
		return validatedEntry;
	}

}
