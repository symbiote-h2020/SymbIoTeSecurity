package eu.h2020.symbiote.security.commons.exceptions.custom;

/**
 * TODO R3, delete it and unify with the @{ eu.h2020.symbiote.security.commons.exceptions.custom
 * .TokenValidationException} by renaming it to ValidationException
 */
public class CertificateVerificationException extends SecurityHandlerException {
    private static final long serialVersionUID = 1L;

    public CertificateVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CertificateVerificationException(String message) {
        super(message);
    }
}
