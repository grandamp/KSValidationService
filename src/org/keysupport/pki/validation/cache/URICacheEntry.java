package org.keysupport.pki.validation.cache;

import java.util.Date;

import org.keysupport.httpclient.PkiUri;

public interface URICacheEntry {

	public static final String HTTP = "http";
	public static final String LDAP = "ldap";

	public Date getLastChecked();
	public void setLastChecked(Date lastChecked);

	public long getLastNumBytes();
	public void setLastNumBytes(long lastNumBytes);

	public Date getNextUpdate();
	public void setNextUpdate(Date nextUpdate);

	public long getLastResponseTime();
	public void setLastResponseTime(long lastResponseTime);
	
	public String getProtocolVersion();
	public void setProtocolVersion(String protocolVersion);
	
	public String getReasonPhrase();
	public void setReasonPhrase(String reasonPhrase);
	
	public int getStatusCode();
	public void setStatusCode(int statusCode);
	
	public PkiUri getPkiUri();
	public void setPkiUri(PkiUri pkiUri);
}
