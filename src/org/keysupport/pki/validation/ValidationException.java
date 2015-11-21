package org.keysupport.pki.validation;

public class ValidationException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1575007744923858612L;

	public ValidationException() {
		super();
	}

	public ValidationException(String message) {
		super(message);
	}

	public ValidationException(Throwable cause) {
		super(cause);
	}

	public ValidationException(String message, Throwable cause) {
		super(message, cause);
	}

}
