package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when platform management request fails
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class PlatformManagementException extends SecurityException {

    public final static String errorMessage = "PLATFORM_MANAGEMENT_ERROR";
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    public static HttpStatus statusCode = HttpStatus.BAD_REQUEST;

    public PlatformManagementException() {
        super(errorMessage);
    }

    public PlatformManagementException(HttpStatus statusCode) {
        super(errorMessage);
        this.statusCode = statusCode;
    }

    public PlatformManagementException(String message, HttpStatus statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public PlatformManagementException(Throwable cause, HttpStatus statusCode) {
        super(cause);
        this.statusCode = statusCode;
    }

    public PlatformManagementException(String message, Throwable cause, HttpStatus statusCode) {
        super(message, cause);
        this.statusCode = statusCode;
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
