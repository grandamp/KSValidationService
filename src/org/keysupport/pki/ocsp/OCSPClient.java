package org.keysupport.pki.ocsp;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.ocsp.OCSPRespStatus;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.keysupport.httpclient.HttpClient;
import org.keysupport.httpclient.HttpClientException;
import org.keysupport.httpclient.PkiUri;
import org.keysupport.pki.validation.cache.CertificateCache;
import org.keysupport.pki.validation.cache.CertificateCacheManager;

public class OCSPClient {

	private static final Log LOG = LogFactory.getLog(CertificateCacheManager.class);
	private HttpClient client = null;

	public static final int GOOD = 0;
	public static final int REVOKED = 1;
	public static final int UNKNOWN = 2;

	public OCSPClient() {
		client = HttpClient.getInstance();
	}

	public int checkRevocation(CertificateCache ca, X509Certificate clientCert,
			PkiUri ocspUri) throws OCSPClientException {

		int revocationStatus = OCSPClient.UNKNOWN;
		long ocspStart = System.currentTimeMillis();

		try {
			// writer.println("getOcspUris: " + uri.toString());
			// HttpClient http = HttpClient.getInstance();
			OCSPReqBuilder gen = new OCSPReqBuilder();
			CertificateID id = new CertificateID(new CertID(ca
					.getSubjectCertId().getHashAlgorithm(), ca
					.getSubjectCertId().getIssuerNameHash(), ca
					.getSubjectCertId().getIssuerKeyHash(), new ASN1Integer(
					clientCert.getSerialNumber())));
			// ca.getSubjectCertId().getIssuerNameHash()//ValidationUtils.getCertIdentifier(ca.getCertificate(),
			// clientCert);
			// new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
			// caCert, clientCert.getSerialNumber());
			gen.addRequest(id);
			OCSPReq req = gen.build();
			byte[] reqBa = req.getEncoded();

			//ASN1InputStream bIn = null;
			//ASN1Primitive obj = null;
			// writer.println("OCSP Request:");
			//bIn = new ASN1InputStream(new ByteArrayInputStream(reqBa));
			//obj = bIn.readObject();
			// writer.println(ASN1Dump.dumpAsString(obj, true));

			byte[] resBa = client.ocspPost(ocspUri, reqBa);
			//TODO:  Add null check
			if (resBa != null) {
				OCSPResp resp = new OCSPResp(resBa);
				if (OCSPRespStatus.SUCCESSFUL == resp.getStatus()) {

					// writer.println("OCSP Response:");
					//bIn = new ASN1InputStream(new ByteArrayInputStream(resBa));
					//obj = bIn.readObject();
					// writer.println(ASN1Dump.dumpAsString(obj, true));

					BasicOCSPResp basicResponse = (BasicOCSPResp) resp
							.getResponseObject();

					/*
					 * Do. Throw exception on fail.
					 * 
					 */
					X509CertificateHolder[] resCerts = basicResponse.getCerts();
					JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
					boolean signatureValid = false;
					for (X509CertificateHolder ch: resCerts) {
						LOG.info("Validating signature of OCSP Response with cert: " + ch.getSubject().toString());
						X509Certificate thisCert = null;
						try {
							thisCert = converter.getCertificate(ch);
							signatureValid = basicResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(thisCert.getPublicKey()));
							if (signatureValid) {
								LOG.info("Signature on OCSP Response is valid.");
								break;
							}
						} catch (CertificateException e) {
							LOG.fatal("Error getting X509Certificate from X509CertificateHolder: " + e.getMessage());
						} catch (OperatorCreationException e) {
							LOG.fatal("Error creating signature verifier: " + e.getMessage());
						}
					}
					if (signatureValid) {
						//TODO: Check to see that the Certificate is either the CA, or signed by the CA
					} else {
						throw new OCSPClientException("Invalid Signature.");
					}

					SingleResp[] responses = basicResponse.getResponses();
					/*
					 * Check each response object and match it to our client. If we
					 * find a hit, then process, otherwise, throw exception
					 */
					for (SingleResp res : responses) {
						if (res.getCertID().equals(id)) {
							Object status = res.getCertStatus();
							if (status == CertificateStatus.GOOD) {
								LOG.info("OCSP Response for " + clientCert.getSubjectX500Principal().getName() + ": GOOD");
								revocationStatus = OCSPClient.GOOD;
							} else if (status instanceof org.bouncycastle.ocsp.RevokedStatus) {
								LOG.info("OCSP Response for " + clientCert.getSubjectX500Principal().getName() + ": REVOKED");
								revocationStatus = OCSPClient.REVOKED;
							} else if (status instanceof org.bouncycastle.ocsp.UnknownStatus) {
								LOG.info("OCSP Response for " + clientCert.getSubjectX500Principal().getName() + ": UNKNOWN");
								revocationStatus = OCSPClient.UNKNOWN;
							}
							break;
						}
					}
				} else {
					revocationStatus = OCSPClient.UNKNOWN;
				}
			} else {
				throw new OCSPClientException("Received a NULL response from the OCSP Responder.");
			}
		} catch (OCSPException e) {
			throw new OCSPClientException(e);
		} catch (HttpClientException e) {
			throw new OCSPClientException(e);
		} catch (IOException e) {
			throw new OCSPClientException(e);
		}
		LOG.info("OCSP Check for " + clientCert.getSubjectX500Principal().getName() + " took " + (System.currentTimeMillis() - ocspStart) + " milliseconds.");
		return revocationStatus;
	}

}
