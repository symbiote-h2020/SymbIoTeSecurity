package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when user management request fails
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class UserManagementException extends SecurityException {

    public final static String errorMessage = "USER_MANAGEMENT_ERROR";
    public static HttpStatus statusCode = HttpStatus.BAD_REQUEST;
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;

    public UserManagementException() {
        super(errorMessage);
    }

    public UserManagementException(HttpStatus statusCode) {
        super(errorMessage);
        this.statusCode = statusCode;
    }

    public UserManagementException(String message, HttpStatus statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public UserManagementException(String message) {
        super(message);
    }

    public UserManagementException(Throwable cause) {
        super(cause);
    }

    public UserManagementException(Throwable cause, HttpStatus statusCode) {
        super(cause);
        this.statusCode = statusCode;
    }

    public UserManagementException(String message, Throwable cause, HttpStatus statusCode) {
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
