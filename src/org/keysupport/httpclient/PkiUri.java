package org.keysupport.httpclient;

import java.net.URI;

/**
 * There may be a CDP defined for a particular revocation reason.
 * 
 * This is a class for a PKIUri, where we will store:
 * 
 * -URI
 * -URI Reason
 * -URI SubReason
 * 
 * I.e.,
 * 
 * URI Reason is one of:  CDP, OCSP, CERTSONLYCMS
 * URI SubReason is one of: AIA, SIA, UNUSED, KEYCOMPROMISE, CACOMPROMISE, AFFILIATIONCHANGED, SUPERSEDED, CESSATIONOFOPERATION, CERTIFICATEHOLD, PRIVILEGEWITHDRAWN, AACOMPROMISE
 */
public class PkiUri {

	/*
	 * The following can be a sub-reason where
	 * there is no sub-reason for the primary
	 * reason.
	 */
	public static final int NOREASON = 0;
	/*
	 * We will keep these sub-reason codes in
	 * sync with RFC 5280 ReasonFlags:
	 * 
	 *    ReasonFlags ::= BIT STRING {
	 *         unused                  (0),
	 *         keyCompromise           (1),
	 *         cACompromise            (2),
	 *         affiliationChanged      (3),
	 *         superseded              (4),
	 *         cessationOfOperation    (5),
	 *         certificateHold         (6),
	 *         privilegeWithdrawn      (7),
	 *         aACompromise            (8) }
	 *
	 */
	public static final int UNUSED = (1 << 7); //128
	public static final int KEYCOMPROMISE = (1 << 6); //64
	public static final int CACOMPROMISE = (1 << 5); //32
	public static final int AFFILIATIONCHANGED = (1 << 4); //16
	public static final int SUPERSEDED = (1 << 3); //8
	public static final int CESSATIONOFOPERATION = (1 << 2); //4
	public static final int CERTIFICATEHOLD = (1 << 1); //2
	public static final int PRIVILEGEWITHDRAWN = (1 << 0); //1
	public static final int AACOMPROMISE = (1 << 15); //32,768
	/*
	 * These sub-reason codes are to clarify the 
	 * certs-only CMS message type.
	 */
	public static final int AIA = (1 << 14); //16,384
	public static final int SIA = (1 << 13); //8,192
	/*
	 * These reason codes are the primary reason 
	 * codes of what the URI are for.  At the moment
	 * we only recognize PKI based URIs for:
	 * 
	 * -cRLDistributionPoints extension
	 *   -CDP URI
	 * -authorityInfoAccess extension
	 *   -OCSP URI
	 *   -CERTSONLYCMS URI
	 * -authorityInfoAccess extension
	 *   -CERTSONLYCMS URI
	 */
	public static final int CDP = (1 << 12); //4,096
	public static final int OCSP = (1 << 11); //2,048
	public static final int CERTSONLYCMS = (1 << 10); //1,024

	private URI uri = null;
	private int reason = NOREASON;
	private int subReason = NOREASON;

	@SuppressWarnings("unused")
	private PkiUri() {
		// Hidden default constructor
	}

	public PkiUri(URI uri, int reason, int subReason) {
		this.uri = uri;
		this.reason = reason;
		this.subReason = subReason;
	}

	/**
	 * @return the uri
	 */
	public URI getUri() {
		return uri;
	}

	/**
	 * @param uri the uri to set
	 */
	public void setUri(URI uri) {
		this.uri = uri;
	}

	/**
	 * @return the reason
	 */
	public int getReason() {
		return reason;
	}

	/**
	 * @param reason the reason to set
	 */
	public void setReason(int reason) {
		this.reason = reason;
	}

	/**
	 * @return the subReason
	 */
	public int getSubReason() {
		return subReason;
	}

	/**
	 * @param subReason the subReason to set
	 */
	public void setSubReason(int subReason) {
		this.subReason = subReason;
	}

	/*
	 * Reasons for a CDP URI could have multiple
	 * reasons set, so the following helper methods
	 * are provided.
	 */

	/**
	 * If the sub-flag UNUSED is set.
	 * 
	 * @return boolean true if set, false otherwise
	 */
	public boolean isSrUnused() {
		return ((PkiUri.UNUSED & this.subReason) == PkiUri.UNUSED);
	}
	
	/**
	 * If the sub-flag KEYCOMPROMISE is set.
	 * 
	 * @return boolean true if set, false otherwise
	 */
	public boolean isSrKeyCompromise() {
		return ((PkiUri.KEYCOMPROMISE & this.subReason) == PkiUri.KEYCOMPROMISE);
	}

	/**
	 * If the sub-flag CACOMPROMISE is set.
	 * 
	 * @return boolean true if set, false otherwise
	 */
	public boolean isSrCaCompromise() {
		return ((PkiUri.CACOMPROMISE & this.subReason) == PkiUri.CACOMPROMISE);
	}

	/**
	 * If the sub-flag AFFILIATIONCHANGED is set.
	 * 
	 * @return boolean true if set, false otherwise
	 */
	public boolean isSrAffiliationChanged() {
		return ((PkiUri.AFFILIATIONCHANGED & this.subReason) == PkiUri.AFFILIATIONCHANGED);
	}

	/**
	 * If the sub-flag SUPERSEDED is set.
	 * 
	 * @return boolean true if set, false otherwise
	 */
	public boolean isSrSuperseded() {
		return ((PkiUri.SUPERSEDED & this.subReason) == PkiUri.SUPERSEDED);
	}

	/**
	 * If the sub-flag CESSATIONOFOPERATION is set.
	 * 
	 * @return boolean true if set, false otherwise
	 */
	public boolean isSrCessationOfOperation() {
		return ((PkiUri.CESSATIONOFOPERATION & this.subReason) == PkiUri.CESSATIONOFOPERATION);
	}

	/**
	 * If the sub-flag CERTIFICATEHOLD is set.
	 * 
	 * @return boolean true if set, false otherwise
	 */
	public boolean isSrCertificateHold() {
		return ((PkiUri.CERTIFICATEHOLD & this.subReason) == PkiUri.CERTIFICATEHOLD);
	}

	/**
	 * If the sub-flag PRIVILEGEWITHDRAWN is set.
	 * 
	 * @return boolean true if set, false otherwise
	 */
	public boolean isSrPrivilegeWithdrawn() {
		return ((PkiUri.PRIVILEGEWITHDRAWN & this.subReason) == PkiUri.PRIVILEGEWITHDRAWN);
	}

	/**
	 * If the sub-flag AACOMPROMISE is set.
	 * 
	 * @return boolean true if set, false otherwise
	 */
	public boolean isSrAaCompromise() {
		return ((PkiUri.AACOMPROMISE & this.subReason) == PkiUri.AACOMPROMISE);
	}

	public boolean equals(Object o) {
		if (!(o instanceof PkiUri)) {
			return false;
		}
		PkiUri pUri = (PkiUri)o;
		return (this.uri == pUri.uri);
	}

	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("URI: [" + uri + "] Reason: ");
		switch(reason) {
		/*
		 * URI Reason CDP may have multiple sub-reasons
		 * set.
		 */
		case PkiUri.CDP: {
			sb.append("[CDP] Sub-Reason:");
			if (this.subReason == PkiUri.NOREASON) {
				sb.append(" [NOREASON]");
			} else {
				if (this.isSrUnused()) {
					sb.append(" [UNUSED]");
				}
				if (this.isSrKeyCompromise()) {
					sb.append(" [KEYCOMPROMISE]");
				}
				if (this.isSrCaCompromise()) {
					sb.append(" [CACOMPROMISE]");
				}
				if (this.isSrAffiliationChanged()) {
					sb.append(" [AFFILIATIONCHANGED]");
				}
				if (this.isSrSuperseded()) {
					sb.append(" [SUPERSEDED]");
				}
				if (this.isSrCessationOfOperation()) {
					sb.append(" [CESSATIONOFOPERATION]");
				}
				if (this.isSrCertificateHold()) {
					sb.append(" [CERTIFICATEHOLD]");
				}
				if (this.isSrPrivilegeWithdrawn()) {
					sb.append(" [PRIVILEGEWITHDRAWN]");
				}
				if (this.isSrAaCompromise()) {
					sb.append(" [AACOMPROMISE]");
				}
			}
			break;
		}
		/*
		 * No sub-reasons for OCSP
		 */
		case PkiUri.OCSP: {
			sb.append("[OCSP] Sub-Reason: [NOREASON]");
			break;
		}
		/*
		 * The sub-reason for a cms certs-only URI 
		 * will be AIA or SIA, not both
		 */
		case PkiUri.CERTSONLYCMS: {
			sb.append("[CERTSONLYCMS] Sub-Reason: ");
			if (subReason == PkiUri.AIA) {
				sb.append("[AIA]");
			} else {
				sb.append("[SIA]");
			}
			break;
		}
		/*
		 * URIs with no reason will not have a sub-reason
		 * either
		 */
		default: {
			sb.append("[NOREASON] Sub-Reason: [NOREASON]");
			break;
		}
		}
		return sb.toString();
	}

	@Override
	public int hashCode() {
		return uri.hashCode();
	}
}
