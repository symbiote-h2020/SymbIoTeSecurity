package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when user is blocked due to anomaly detection.
 *
 * @author Piotr Jakubowski (PCSS)
 */
public class BlockedUserException extends SecurityException {

    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    private final static String errorMessage = "ERR_BLOCKED_USER";
    private final static HttpStatus statusCode = HttpStatus.FORBIDDEN;

    public BlockedUserException() {
        super(errorMessage);
    }

    public BlockedUserException(String message) {
        super(message);
    }

    public BlockedUserException(Throwable cause) {
        super(cause);
    }

    public BlockedUserException(String message, Throwable cause) {
        super(message, cause);
    }

    @Override
    public HttpStatus getStatusCode() {
        return statusCode;
    }

    @Override
    public String getErrorMessage() {
        return errorMessage;
    }

}
