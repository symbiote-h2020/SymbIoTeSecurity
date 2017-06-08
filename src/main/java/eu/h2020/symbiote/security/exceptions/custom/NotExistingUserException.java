package eu.h2020.symbiote.security.exceptions.custom;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when user credentials are not present in DB during unregistration procedure
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class NotExistingUserException extends SecurityException {

    private static final long serialVersionUID = AAMConstants.serialVersionUID;
    private final static String errorMessage = "USER_NOT_REGISTERED_IN_REPOSITORY";
    private final static HttpStatus statusCode = HttpStatus.BAD_REQUEST;

    public NotExistingUserException() {
        super(errorMessage);
    }

    public NotExistingUserException(String message) {
        super(message);
    }

    public NotExistingUserException(Throwable cause) {
        super(cause);
    }

    public NotExistingUserException(String message, Throwable cause) {
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