package org.keysupport.pki.validation.cache;

import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.keysupport.httpclient.PkiUri;

public class HttpURICacheEntry implements URICacheEntry {

	//TODO: Add LOGGING!

	private Date lastChecked = null;
	private long lastNumBytes = 0;
	private Date nextUpdate = null;
	private long lastResponseTime = 0;
	private String protocolVersion = null;
	private String reasonPhrase = null;
	private int statusCode = 0;
	private PkiUri pkiUri = null;

	public HttpURICacheEntry(HttpResponse response, long responseTime) {
		this.lastChecked = Calendar.getInstance().getTime();
		HttpEntity resEntity = null;
		if ((resEntity = response.getEntity()) != null) {
			this.lastNumBytes = resEntity.getContentLength();
		} else {
			this.lastNumBytes = 0;
		}
		/*
		 * Get the cache-control header and calculate
		 * our next update if possible.  Meaning, we should
		 * not visit this URL until the next update to be polite.
		 */
		Header[] headers = response.getHeaders(HttpHeaders.CACHE_CONTROL);
		if (headers.length <= 0) {
			this.nextUpdate = Calendar.getInstance().getTime();
		} else {
			for (Header header: headers) {
				HeaderElement[] elements = header.getElements();
				for (HeaderElement element: elements) {
					if (element.getName() != null && element.getName().contains("max-age")) {
						if (element.getValue() != null && StringUtils.isNumeric(element.getValue())) {
							Calendar next = Calendar.getInstance();
							next.add(Calendar.SECOND, new Integer(element.getValue()).intValue());
							this.nextUpdate = next.getTime();
						}
					} else if (element.getName() != null && element.getName().contains("no-cache")) {
						this.nextUpdate = Calendar.getInstance().getTime();
					}
				}
			}
		}
		this.lastResponseTime = responseTime;
		StatusLine lastStatus = response.getStatusLine();
		this.protocolVersion = lastStatus.getProtocolVersion().getProtocol();
		this.reasonPhrase = lastStatus.getReasonPhrase();
		this.statusCode = lastStatus.getStatusCode();
	}

	/**
	 * @return the lastChecked
	 */
	public Date getLastChecked() {
		return lastChecked;
	}

	/**
	 * @param lastChecked the lastChecked to set
	 */
	public void setLastChecked(Date lastChecked) {
		this.lastChecked = lastChecked;
	}

	/**
	 * @return the lastNumBytes
	 */
	public long getLastNumBytes() {
		return lastNumBytes;
	}

	/**
	 * @param lastNumBytes the lastNumBytes to set
	 */
	public void setLastNumBytes(long lastNumBytes) {
		this.lastNumBytes = lastNumBytes;
	}

	/**
	 * @return the nextUpdate
	 */
	public Date getNextUpdate() {
		return nextUpdate;
	}

	/**
	 * @param nextUpdate the nextUpdate to set
	 */
	public void setNextUpdate(Date nextUpdate) {
		this.nextUpdate = nextUpdate;
	}

	/**
	 * @return the lastResponseTime
	 */
	public long getLastResponseTime() {
		return lastResponseTime;
	}

	/**
	 * @param lastResponseTime the lastResponseTime to set
	 */
	public void setLastResponseTime(long lastResponseTime) {
		this.lastResponseTime = lastResponseTime;
	}

	/**
	 * @return the protocolVersion
	 */
	public String getProtocolVersion() {
		return protocolVersion;
	}

	/**
	 * @param protocolVersion the protocolVersion to set
	 */
	public void setProtocolVersion(String protocolVersion) {
		this.protocolVersion = protocolVersion;
	}

	/**
	 * @return the reasonPhrase
	 */
	public String getReasonPhrase() {
		return reasonPhrase;
	}

	/**
	 * @param reasonPhrase the reasonPhrase to set
	 */
	public void setReasonPhrase(String reasonPhrase) {
		this.reasonPhrase = reasonPhrase;
	}

	/**
	 * @return the statusCode
	 */
	public int getStatusCode() {
		return statusCode;
	}

	/**
	 * @param statusCode the statusCode to set
	 */
	public void setStatusCode(int statusCode) {
		this.statusCode = statusCode;
	}

	/**
	 * @return the pkiUri
	 */
	public PkiUri getPkiUri() {
		return pkiUri;
	}

	/**
	 * @param pkiUri the pkiUri to set
	 */
	public void setPkiUri(PkiUri pkiUri) {
		this.pkiUri = pkiUri;
	}

}
