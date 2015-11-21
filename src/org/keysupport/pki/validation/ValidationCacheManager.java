package org.keysupport.pki.validation;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ocsp.CertID;
import org.keysupport.httpclient.PkiUri;
import org.keysupport.pki.validation.cache.CertificateCache;
import org.keysupport.pki.validation.cache.CertificateCacheException;
import org.keysupport.pki.validation.cache.CertificateCacheManager;
import org.keysupport.pki.validation.cache.RejectedCertCacheEntry;
import org.keysupport.pki.validation.cache.RejectedCertCacheManager;
import org.keysupport.pki.validation.cache.URICache;
import org.keysupport.pki.validation.cache.URICacheEntry;
import org.keysupport.pki.validation.cache.UriCacheManager;

public final class ValidationCacheManager extends HttpServlet {
	
	//Command to viewCache is the default, so no variable here
	private final static String commandBuildCache = "buildCache";
	private final static String commandResetCache = "resetCache";
	private final static String commandGetCacheAsPem = "getCacheAsPem";
	private final static String commandGetCertPath = "getCertPath";
	//TODO:  Add LOGGING!
	
	/**
		 * 
		 */
	private static final long serialVersionUID = 2425803540456313416L;

	public void viewCache(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		response.setContentType("text/html");
		PrintWriter writer = response.getWriter();

		writer.println("<html>");
		writer.println("<head>");
		writer.println("<title>Validation Cache Detail</title>");
		writer.println("</head>");
		writer.println("<body bgcolor=white>");

		writer.println("<table border=\"0\">");

		writer.println("<tr>");
		CertificateCacheManager manager = CertificateCacheManager.getInstance();
		CertificateCache cache = manager.getCache();
		writer.println("<pre>");
		writer.println("Trust Anchor:");
		writer.println(cache.toString());
		writer.println("</pre>");
		writer.println("</tr>");

		writer.println("<tr>");
		writer.println("URI Cache:");
		writer.println("</tr>");

		URICache uriCache = UriCacheManager.getInstance().getSuccessfulURICache();
		PkiUri[] uris = uriCache.getURIs();
		writer.println("<tr>");
		writer.println("<table align=center border=\"1\" width=\"100%\">");
		writer.println("<tr>");
		writer.println("<th> URI </th>");
		writer.println("<th> Last Checked </th>");
		writer.println("<th> Bytes Received </th>");
		writer.println("<th> Next Update </th>");
		writer.println("<th> Response Time </th>");
		writer.println("<th> Protocol Version </th>");
		writer.println("<th> Reason Phrase </th>");
		writer.println("<th> Status Code </th>");
		writer.println("</tr>");
		for (PkiUri uri: uris) {
			URICacheEntry entry = null;
			String uriStr = uri.toString();
			String lastChecked = null;
			long lastNumBytes = 0;
			String nextUpdate = null;
			long lastResponseTime = 0;
			String protocolVersion = null;
			String reasonPhrase = null;
			int statusCode = 0;
			if ((entry = uriCache.getUriCacheEntry(uri)) != null) {
				if (entry.getLastChecked() != null) {
					lastChecked = entry.getLastChecked().toString();
				}
				lastNumBytes = entry.getLastNumBytes();
				if (entry.getNextUpdate() != null) {
					nextUpdate = entry.getNextUpdate().toString();
				}
				lastResponseTime = entry.getLastResponseTime();
				protocolVersion = entry.getProtocolVersion();
				reasonPhrase = entry.getReasonPhrase();
				statusCode = entry.getStatusCode();
			}
			writer.println("<tr>");
			writer.println("<td align=left>" + uriStr + "</td>");
			writer.println("<td align=left>" + lastChecked + "</td>");
			writer.println("<td align=left>" + lastNumBytes + "</td>");
			writer.println("<td align=left>" + nextUpdate + "</td>");
			writer.println("<td align=left>" + lastResponseTime + "</td>");
			writer.println("<td align=left>" + protocolVersion + "</td>");
			writer.println("<td align=left>" + reasonPhrase + "</td>");
			writer.println("<td align=left>" + statusCode + "</td>");
			writer.println("</tr>");
		}
		writer.println("</table><br>");
		writer.println("</tr>");

		manager = CertificateCacheManager.getInstance();
		Collection<CertificateCache> intermediates = manager.getAllIntermediateEntries();
		writer.println("Flattened Cache contains " + intermediates.size() + " objects:");
		for (CertificateCache entry: intermediates) {
			StringBuffer sb = new StringBuffer();
			sb.append("<a href=\"/KSValidationService/CacheManager/GetCertPath?CertID=");
			sb.append(ValidationUtils.getUrlSafeB64(entry.getSubjectCertId().getEncoded()));
			sb.append("\">PEM Cert Path for: " + entry.getCertificate().getSubjectX500Principal().getName());
			sb.append("</a>");
			writer.println("<tr>");
			writer.println("<pre>");
			writer.println(sb.toString());
			writer.println("</pre><br>");
			writer.println("</tr>");
			sb = new StringBuffer();
			String pemCert = null;
			try {
				pemCert = ValidationUtils.certToPem(entry.getCertificate());
			} catch (ValidationException e1) {
				e1.printStackTrace();
			}
			if (pemCert != null) {
				String subject = ("subject=" + entry.getCertificate().getSubjectX500Principal().getName() + "\n");
				String issuer = ("issuer=" + entry.getCertificate().getIssuerX500Principal().getName() + "\n");
				sb.append(subject);
				sb.append(issuer);
				sb.append(pemCert);
				writer.println("<tr>");
				writer.println("<pre>");
				writer.println(sb.toString());
				writer.println("</pre><br>");
				writer.println("</tr>");
			}
			writer.println("<tr>");
			writer.println("<pre>");
			writer.println(entry.toString());
			writer.println("</pre><br>");
			writer.println("</tr>");
			
//			try {
//				if (entry.hasOcspAccessMethod()) {
//					for (PkiUri uri: entry.getOcspUris()) {
//						CertificateCache issuer = manager.getSigner(entry.getIssuerCertId());
//						int res = ocspCli.checkRevocation(issuer, entry.getCertificate(), uri);
//						writer.print("OCSP Status for above Certificate: ");
//						switch(res) {
//						case OCSPClient.GOOD: {
//							writer.println("GOOD");
//							break;
//						}
//						case OCSPClient.REVOKED: {
//							writer.println("REVOKED");
//							break;
//						}
//						default: {
//							writer.println("UNKNOWN");
//							break;
//						}
//						}
//					}
//				}
//			} catch(OCSPClientException e) {
//				e.printStackTrace();
//			} catch (CertificateCacheException e) {
//				e.printStackTrace();
//			}
		}

		writer.println("<tr>");
		writer.println("Failed URI Cache:");
		writer.println("</tr>");

		URICache failedUriCache = UriCacheManager.getInstance().getFailedUriCache();
		PkiUri[] fUris = failedUriCache.getURIs();
		writer.println("<tr>");
		writer.println("<table align=center border=\"1\" width=\"100%\">");
		writer.println("<tr>");
		writer.println("<th> URI </th>");
		writer.println("<th> Last Checked </th>");
		writer.println("<th> Bytes Received </th>");
		writer.println("<th> Next Update </th>");
		writer.println("<th> Response Time </th>");
		writer.println("<th> Protocol Version </th>");
		writer.println("<th> Reason Phrase </th>");
		writer.println("<th> Status Code </th>");
		writer.println("</tr>");
		for (PkiUri uri: fUris) {
			URICacheEntry entry = null;
			String uriStr = uri.toString();
			String lastChecked = null;
			long lastNumBytes = 0;
			String nextUpdate = null;
			long lastResponseTime = 0;
			String protocolVersion = null;
			String reasonPhrase = null;
			int statusCode = 0;
			if ((entry = failedUriCache.getUriCacheEntry(uri)) != null) {
				if (entry.getLastChecked() != null) {
					lastChecked = entry.getLastChecked().toString();
				}
				lastNumBytes = entry.getLastNumBytes();
				if (entry.getNextUpdate() != null) {
					nextUpdate = entry.getNextUpdate().toString();
				}
				lastResponseTime = entry.getLastResponseTime();
				protocolVersion = entry.getProtocolVersion();
				reasonPhrase = entry.getReasonPhrase();
				statusCode = entry.getStatusCode();
			}
			writer.println("<tr>");
			writer.println("<td align=left>" + uriStr + "</td>");
			writer.println("<td align=left>" + lastChecked + "</td>");
			writer.println("<td align=left>" + lastNumBytes + "</td>");
			writer.println("<td align=left>" + nextUpdate + "</td>");
			writer.println("<td align=left>" + lastResponseTime + "</td>");
			writer.println("<td align=left>" + protocolVersion + "</td>");
			writer.println("<td align=left>" + reasonPhrase + "</td>");
			writer.println("<td align=left>" + statusCode + "</td>");
			writer.println("</tr>");
		}
		writer.println("</table><br>");
		writer.println("</tr>");

		writer.println("<tr>");
		writer.println("<pre>");
		RejectedCertCacheManager rejectManager = RejectedCertCacheManager.getInstance();
		RejectedCertCacheEntry[] rejects = rejectManager.getRejectedCache().getRejectedCerts();
		writer.println("Rejected Certificate Cache contains " + rejects.length + " objects:");
		for (RejectedCertCacheEntry reject: rejects) {
			writer.println(reject.toString());
		}
		writer.println("</pre><br>");
		writer.println("</tr>");

		writer.println("</table><br>");

		writer.println("</body>");
		writer.println("</html>");		
	}

	public void getCacheAsPem(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		
		response.setContentType("text/html");
		PrintWriter writer = response.getWriter();
		
		CertificateCacheManager manager = CertificateCacheManager.getInstance();
		Iterator<CertificateCache> fCache = manager.getFlattenedCache();
		if (fCache != null && fCache.hasNext()) {
			StringBuffer sb = new StringBuffer();
			sb.append("<html>\n");
			sb.append("<head>\n");
			sb.append("<title>Validation Cache Detail</title>\n");
			sb.append("</head>\n");
			sb.append("<body bgcolor=white>\n");
			while (fCache.hasNext()) {
				CertificateCache cCert = fCache.next();
				
				String pemCert = null;
				try {
					pemCert = ValidationUtils.certToPem(cCert.getCertificate());
				} catch (ValidationException e) {
					e.printStackTrace();
				}
				if (pemCert != null) {
					sb.append("<pre>\n");
					String subject = ("subject=" + cCert.getCertificate().getSubjectX500Principal().getName() + "\n");
					String issuer = ("issuer=" + cCert.getCertificate().getIssuerX500Principal().getName() + "\n");
					sb.append(subject);
					sb.append(issuer);
					sb.append(pemCert);
					sb.append("</pre>\n");
				}
			}
			sb.append("</body>\n");
			sb.append("</html>\n");
			sb.append("</html>\n");
			writer.println(sb.toString());
		}

	}

	public void getCertPath(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		
		response.setContentType("text/html");
		PrintWriter writer = response.getWriter();
		
		String certIDParam = null;
		Enumeration<String> pn = request.getParameterNames();
		while (pn.hasMoreElements()) {
			String param = pn.nextElement();
			if (param.equalsIgnoreCase("CertID")) {
				certIDParam = param;
				break;
			}
		}

		
		if (certIDParam == null && request.getParameter(certIDParam) == null) {
			writer.println("<html>");
			writer.println("Not Implemented.  Missing CertID.");
			writer.println("</html>");
		} else {
			
			CertID certId = null;
			
			try {
				String certIdStr = request.getParameter(certIDParam);
				byte[] certIdBa = ValidationUtils.decodeFromUrlSafeB64(certIdStr);
				certId = CertID.getInstance(ASN1Primitive.fromByteArray(certIdBa));
			} catch (Exception e) {
				writer.println("<html>");
				writer.println("Error Parsing CertID: " + e.getMessage());
				writer.println("</html>");
			}
			
			if (certId != null) {
				
				//Get manager
				CertificateCacheManager manager = CertificateCacheManager.getInstance();
				//Get cert path from manager
				Iterator<CertificateCache> path = null;
				try {
					path = manager.getSignerPath(certId);
				} catch (CertificateCacheException e) {
					e.printStackTrace();
				}

				if (path != null && path.hasNext()) {
					StringBuffer sb = new StringBuffer();
					sb.append("<html>\n");
					sb.append("<head>\n");
					sb.append("<title>Validation Cache Detail</title>\n");
					sb.append("</head>\n");
					sb.append("<body bgcolor=white>\n");
					while (path.hasNext()) {
						CertificateCache cCert = path.next();
						
						String pemCert = null;
						try {
							pemCert = ValidationUtils.certToPem(cCert.getCertificate());
						} catch (ValidationException e) {
							e.printStackTrace();
						}
						if (pemCert != null) {
							sb.append("<pre>\n");
							String subject = ("subject=" + cCert.getCertificate().getSubjectX500Principal().getName() + "\n");
							String issuer = ("issuer=" + cCert.getCertificate().getIssuerX500Principal().getName() + "\n");
							sb.append(subject);
							sb.append(issuer);
							sb.append(pemCert);
							sb.append("</pre>\n");
						}
					}
					sb.append("</body>\n");
					sb.append("</html>\n");
					sb.append("</html>\n");
					writer.println(sb.toString());
				}
			}
			
		}

	}

	public void doGet(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {

		String pathInfo = null;
		if ((pathInfo = request.getPathInfo()) != null && pathInfo.contains("/")) {
			String[] commands = pathInfo.split("/");
			ArrayList<String> parsedCommands = new ArrayList<String>();
			for (String command : commands) {
				if (command != null && !command.equals("")) {
					parsedCommands.add(command.toUpperCase());
				}
			}
			
			if (parsedCommands.contains(commandBuildCache.toUpperCase())) {
				this.viewCache(request, response);
			} else if (parsedCommands.contains(commandResetCache.toUpperCase())) {
				this.viewCache(request, response);
			} else if (parsedCommands.contains(commandGetCacheAsPem.toUpperCase())) {
				this.getCacheAsPem(request, response);
			} else if (parsedCommands.contains(commandGetCertPath.toUpperCase())) {
				this.getCertPath(request, response);
			} else {
				this.viewCache(request, response);
			}
		}else {
			this.viewCache(request, response);
		}

	}

	public void doPost(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {

		response.setContentType("text/html");
		PrintWriter writer = response.getWriter();
		writer.println("<html>");
		writer.println("Not Implemented.");
		writer.println("</html>");
	}
}
