package eu.h2020.symbiote.security.exceptions.custom;

import eu.h2020.symbiote.security.constants.SecurityConstants;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when an unauthorized client tries to register a user or platform.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class UnauthorizedRegistrationException extends SecurityException {

    public final static String errorMessage = "UNAUTHORIZED_REGISTRATION";
    public final static HttpStatus statusCode = HttpStatus.UNAUTHORIZED;
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;

    public UnauthorizedRegistrationException() {
        super(errorMessage);
    }

    public UnauthorizedRegistrationException(String message) {
        super(message);
    }

    public UnauthorizedRegistrationException(Throwable cause) {
        super(cause);
    }

    public UnauthorizedRegistrationException(String message, Throwable cause) {
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
