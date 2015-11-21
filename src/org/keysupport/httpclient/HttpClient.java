package org.keysupport.httpclient;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolVersion;
import org.apache.http.StatusLine;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.message.BasicStatusLine;
import org.keysupport.pki.validation.cache.HttpURICacheEntry;
import org.keysupport.pki.validation.cache.UriCacheManager;

public class HttpClient {

	private static final Log LOG = LogFactory.getLog(HttpClient.class);

	private static HttpClient instance = null;
	private HttpClientContext context = null;
	private CloseableHttpClient httpClient = null;
	private PoolingHttpClientConnectionManager cm = null;
	private UriCacheManager uriCm = null;

	/*
	 * TODO:  Move the following to properties
	 */
	private int timeout = 30;
	
	public static synchronized HttpClient getInstance() {
		if (instance == null) {
			instance = new HttpClient();
		}
		return instance;
	}

	private HttpClient() {

		cm = new PoolingHttpClientConnectionManager();
		// Increase max total connection to 200
		cm.setMaxTotal(200);
		// Increase default max connection per route to 20
		cm.setDefaultMaxPerRoute(20);
		// Increase max connections for localhost:80 to 50

		context = HttpClientContext.create();

		/*
		 * TODO: Since we implement a timeout, we should manage another
		 * URI cache that includes the problematic URI.
		 */

		RequestConfig config = RequestConfig.custom()
				  .setConnectTimeout(timeout * 1000)
				  .setConnectionRequestTimeout(timeout * 1000)
				  .setSocketTimeout(timeout * 1000).build();
		
		httpClient = HttpClients.custom()
		        .setConnectionManager(cm)
		        .setDefaultRequestConfig(config)
		        .build();

		/*
		 * TODO:  Build a trust manager and ALLOW_ANY hostname verifier.
		 * 
		 * We don't care about SSL, as it is bad practice to offer
		 * CA validation data via HTTPS.
		 * 
		final SSLContext sslContext = SslContextFactory.getContext();

		final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext,
				SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER);

		// Initialize the Apache Pooling Connection Manager
		final Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder
				.<ConnectionSocketFactory> create()
				.register("https", sslsf).build();
		cm = new PoolingHttpClientConnectionManager(socketFactoryRegistry);

		cm.setMaxTotal(200);
		cm.setDefaultMaxPerRoute(200);
		httpClient = HttpClients.custom().setConnectionManager(cm).build();
		*/
	}

	public byte[] getRequest(final PkiUri url) throws HttpClientException {

		CloseableHttpResponse response = null;
		long startTime = 0;
		long responseTime = 0;
		uriCm = UriCacheManager.getInstance();
		

		try {
			final HttpGet httpget = new HttpGet(url.getUri());
			httpget.setHeader(HttpHeaders.USER_AGENT, "IDevity Client");
			LOG.info("Executing request " + httpget.getRequestLine());
			startTime = System.currentTimeMillis();
			response = httpClient.execute(httpget, context);
			responseTime = System.currentTimeMillis() - startTime;
			HttpURICacheEntry ce = new HttpURICacheEntry(response, responseTime);
			uriCm.update(url, ce);

			final int statusCode = response.getStatusLine().getStatusCode();
			LOG.info("Status Code " + statusCode);
			LOG.info("Full Response: " + response.toString());

			/*
			 * Any redirects should be automatically followed.
			 * Anything other than a 200 will be considered a fail.
			 */
			if (statusCode != 200) {
				uriCm.update(url, ce);
				response.close();
				return null;
			} else {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				response.getEntity().writeTo(baos);
				response.close();
				return baos.toByteArray();
			}
		}
		catch (final UnknownHostException e) {
			responseTime = System.currentTimeMillis() - startTime;
			failedResponse(url, e.getMessage(), responseTime);
			LOG.fatal("DNS or Connectivity error?:");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		}
		catch(final ConnectTimeoutException e) {
			responseTime = System.currentTimeMillis() - startTime;
			failedResponse(url, e.getMessage(), responseTime);
			LOG.fatal("Timeout Reached: Current Timeout: " + timeout + " seconds: ");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		}
		catch(final SocketTimeoutException e) {
			responseTime = System.currentTimeMillis() - startTime;
			failedResponse(url, e.getMessage(), responseTime);
			LOG.fatal("Timeout Reached: Current Timeout: " + timeout + " seconds: ");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		}
		catch(final ConnectException e) {
			responseTime = System.currentTimeMillis() - startTime;
			failedResponse(url, e.getMessage(), responseTime);
			LOG.fatal("Timeout Reached: Current Timeout: " + timeout + " seconds: ");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		}
		catch (final Exception e) {
			responseTime = System.currentTimeMillis() - startTime;
			failedResponse(url, e.getMessage(), responseTime);
			LOG.fatal("Common Error? Catch and re-throw explicitly!:", e);
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		}
		finally {
			try {
				if (response != null) {
					response.close();
				}
			}
			catch (final IOException e) {
				LOG.fatal("Exception when closing response in catch block:", e);
				throw new HttpClientException("Exception while closing response for [" + url + "]", e);
			}
		}
	}

	private void failedResponse(PkiUri uri, String reason, long responseTime) {
		uriCm = UriCacheManager.getInstance();
		StatusLine fstatus = new BasicStatusLine(new ProtocolVersion("N/A", 0, 0), 0, reason);
		HttpResponse fres = new BasicHttpResponse(fstatus);
		HttpURICacheEntry fce = new HttpURICacheEntry(fres, responseTime);
		uriCm.update(uri, fce);
	}

	public byte[] ocspPost(final PkiUri url, byte[] reqBa) throws HttpClientException {

		CloseableHttpResponse response = null;
		long startTime = 0;
		long responseTime = 0;
		uriCm = UriCacheManager.getInstance();

		try {
			final HttpPost httppost = new HttpPost(url.getUri());
			httppost.setHeader(HttpHeaders.USER_AGENT, "IDevity Client");
			httppost.setHeader(HttpHeaders.CONTENT_TYPE, "application/ocsp-request");
			HttpEntity ocspReq = new ByteArrayEntity(reqBa);
			httppost.setEntity(ocspReq);
			LOG.info("Executing request " + httppost.getRequestLine());

			startTime = System.currentTimeMillis();
			response = httpClient.execute(httppost, context);
			responseTime = System.currentTimeMillis() - startTime;
			HttpURICacheEntry ce = new HttpURICacheEntry(response, responseTime);
			uriCm.update(url, ce);

			final int statusCode = response.getStatusLine().getStatusCode();
			LOG.debug("Status Code " + statusCode);
			LOG.debug("Full Response: " + response.toString());

			/*
			 * Any redirects should be automatically followed.
			 * Anything other than a 200 will be considered a fail.
			 */
			if (statusCode != 200) {
				uriCm.update(url, ce);
				response.close();
				return null;
			} else {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				response.getEntity().writeTo(baos);
				response.close();
				return baos.toByteArray();
			}
		}
		catch (final UnknownHostException e) {
			responseTime = System.currentTimeMillis() - startTime;
			failedResponse(url, e.getMessage(), responseTime);
			LOG.fatal("DNS or Connectivity error?:");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		}
		catch(final ConnectTimeoutException e) {
			responseTime = System.currentTimeMillis() - startTime;
			failedResponse(url, e.getMessage(), responseTime);
			LOG.fatal("Timeout Reached: Current Timeout: " + timeout + " seconds: ");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		}
		catch(final SocketTimeoutException e) {
			responseTime = System.currentTimeMillis() - startTime;
			failedResponse(url, e.getMessage(), responseTime);
			LOG.fatal("Timeout Reached: Current Timeout: " + timeout + " seconds: ");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		}
		catch(final ConnectException e) {
			responseTime = System.currentTimeMillis() - startTime;
			failedResponse(url, e.getMessage(), responseTime);
			LOG.fatal("Timeout Reached: Current Timeout: " + timeout + " seconds: ");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		}
		catch (final Exception e) {
			responseTime = System.currentTimeMillis() - startTime;
			failedResponse(url, e.getMessage(), responseTime);
			LOG.fatal("Common Error? Catch and re-throw explicitly!:", e);
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		}
		finally {
			try {
				if (response != null) {
					response.close();
				}
			}
			catch (final IOException e) {
				throw new HttpClientException("Exception while closing response for [" + url + "]", e);
			}
		}
	}

//	@Override
//	public void finalize() {
//		if (cm != null) {
//			cm.shutdown();
//		}
//	}

}
