package eu.h2020.symbiote.security.token;

import eu.h2020.symbiote.security.exception.SecurityHandlerException;

public class TokenVerificationException extends SecurityHandlerException {
    private static final long serialVersionUID = 1L;
 
    public TokenVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
 
    public TokenVerificationException(String message) {
        super(message);
    }
}
