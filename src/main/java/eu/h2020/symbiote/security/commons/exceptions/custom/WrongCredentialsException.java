package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when a app/user provides wrong credentials during login procedure
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class WrongCredentialsException extends SecurityException {

    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    public static final String AUTHENTICATION_OF_USER_FAILED = "Authentication of user failed";
    public static final String CLIENT_NOT_EXIST = "Client doesn't exist";
    public static final String NO_SUCH_SERVICE = "There is no such service";
    public static final String USER_NOT_EQUALS_CN = "User is not equal to user from CN";
    public static final String CERTIFICATE_NOT_EQUALS_DB = "Passed certificate do not equals with this in DB";
    public static final String USER_OR_CLIENT_NOT_EXIST = "User or client doesn't exist";
    public static final String AAM_CAN_REVOKE_ONLY_LOCAL_COMPONENTS = "AAM can revoke only local components certificates";
    public static final String CERTIFICATE_COMMON_NAME_IS_WRONG = "Certificate common name is wrong";
    private static final String errorMessage = "ERR_WRONG_CREDENTIALS";
    private HttpStatus statusCode = HttpStatus.UNAUTHORIZED;
    public static final String INVALID_REQUEST = "Request is invalid.";

    public WrongCredentialsException() {
        super(errorMessage);
    }

    public WrongCredentialsException(String message, HttpStatus statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public WrongCredentialsException(String message) {
        super(message);
    }

    public WrongCredentialsException(Throwable cause) {
        super(cause);
    }

    public WrongCredentialsException(String message, Throwable cause) {
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
