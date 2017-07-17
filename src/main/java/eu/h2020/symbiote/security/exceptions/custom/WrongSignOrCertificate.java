package eu.h2020.symbiote.security.exceptions.custom;

import eu.h2020.symbiote.security.constants.SecurityConstants;
import org.springframework.http.HttpStatus;

/**
 * Created by Jakub on 14.07.2017.
 */
public class WrongSignOrCertificate extends SecurityException {
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    private final static String ERROR_MESSAGE = "Sign can't be verified using cerified public key";
    private final static HttpStatus statusCode = HttpStatus.UNAUTHORIZED;

    public WrongSignOrCertificate() {
        super(ERROR_MESSAGE);
    }

    public WrongSignOrCertificate(String message) {
        super(message);
    }

    public WrongSignOrCertificate(Throwable cause) {
        super(cause);
    }

    public WrongSignOrCertificate(String message, Throwable cause) {
        super(message, cause);
    }

    public HttpStatus getStatusCode() {
        return statusCode;
    }

    public String getErrorMessage() {
        return ERROR_MESSAGE;
    }

}
