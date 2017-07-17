package eu.h2020.symbiote.security.exceptions.custom;

import eu.h2020.symbiote.security.constants.SecurityConstants;
import org.springframework.http.HttpStatus;

/**
 * Created by Jakub on 14.07.2017.
 */
public class NoClientIdCertificate extends SecurityException {
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    private final static String ERROR_MESSAGE = "Certificate for given clientId was not found";
    private final static HttpStatus statusCode = HttpStatus.UNAUTHORIZED;

    public NoClientIdCertificate() {
        super(ERROR_MESSAGE);
    }

    public NoClientIdCertificate(String message) {
        super(message);
    }

    public NoClientIdCertificate(Throwable cause) {
        super(cause);
    }

    public NoClientIdCertificate(String message, Throwable cause) {
        super(message, cause);
    }

    public HttpStatus getStatusCode() {
        return statusCode;
    }

    public String getErrorMessage() {
        return ERROR_MESSAGE;
    }

}
