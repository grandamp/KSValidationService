package org.keysupport.pki.ocsp;

public class OCSPClientException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 569198975620688377L;

	public OCSPClientException() {
		super();
	}

	public OCSPClientException(String message) {
		super(message);
	}

	public OCSPClientException(Throwable cause) {
		super(cause);
	}

	public OCSPClientException(String message, Throwable cause) {
		super(message, cause);
	}

}
