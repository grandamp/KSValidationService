package org.keysupport.pki.validation.cache;

import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class RejectedCertCacheEntry {

	//TODO: Add LOGGING!

	private X509Certificate rejectedCert = null;
	private String rejectedReason = null;
	private Date dateAdded = null;
	private String rejectedCertSource = null;

	public RejectedCertCacheEntry(X509Certificate rejectedCert, String rejectedReason, String rejectedCertSource) {
		this.dateAdded = Calendar.getInstance().getTime();
		this.rejectedCert = rejectedCert;
		this.rejectedReason = rejectedReason;
		this.rejectedCertSource = rejectedCertSource;
	}

	/**
	 * @return the rejectedCert
	 */
	public X509Certificate getRejectedCert() {
		return rejectedCert;
	}

	/**
	 * @return the rejectedReason
	 */
	public String getRejectedReason() {
		return rejectedReason;
	}

	/**
	 * @return the dateAdded
	 */
	public Date getDateAdded() {
		return dateAdded;
	}

	/**
	 * @return the rejectedCertSource
	 */
	public String getRejectedCertSource() {
		return rejectedCertSource;
	}

	/**
	 * @return A String representation of this object.
	 */
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("[\n");
		sb.append("  Rejected Reason: " + this.rejectedReason + "\n");
		sb.append("  Source: " + this.rejectedCertSource + "\n");
		sb.append("  Rejected Date: " + this.dateAdded.toString() + "\n");
		sb.append("  Version: V" + this.rejectedCert.getVersion() + "\n");
		sb.append("  Subject: " + this.rejectedCert.getSubjectX500Principal().toString() + "\n");
		sb.append("  Signature Algorithm: " + this.rejectedCert.getSigAlgName() + ", OID = " + this.rejectedCert.getSigAlgOID() + "\n");
		sb.append("  Key:  " + this.rejectedCert.getPublicKey().toString() + "\n");
		sb.append("  Validity: [From: " + this.rejectedCert.getNotBefore().toString() + ",\n");
		sb.append("               To: " + this.rejectedCert.getNotAfter().toString() + "]\n");
		sb.append("  Issuer: " + this.rejectedCert.getIssuerX500Principal().toString() + "\n");
		sb.append("  SerialNumber: " + this.rejectedCert.getSerialNumber().toString() + ", HEX=" + DataUtil.byteArrayToString(this.rejectedCert.getSerialNumber().toByteArray()) + "\n");
		sb.append("]\n");
		return sb.toString();
	}

}
