package eu.h2020.symbiote.security.exceptions.custom;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when the AAM is misconfigured and attempted to run in this state
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class SecurityMisconfigurationException extends SecurityException {

    private static final long serialVersionUID = AAMConstants.serialVersionUID;
    private final static String errorMessage = "AAM_MISCONFIGURED";
    private final static HttpStatus statusCode = HttpStatus.INTERNAL_SERVER_ERROR;

    public SecurityMisconfigurationException() {
        super(errorMessage);
    }

    public SecurityMisconfigurationException(String message) {
        super(message);
    }

    public SecurityMisconfigurationException(Throwable cause) {
        super(cause);
    }

    public SecurityMisconfigurationException(String message, Throwable cause) {
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
