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
public class SspManagementException extends SecurityException {

    public static final String errorMessage = "SSP_MANAGEMENT_ERROR";
    public static final String INVALID_OPERATION = "Invalid operation";
    public static final String USER_IS_NOT_A_SSP_OWNER = "User is not a SSP Owner";
    public static final String WRONG_WAY_TO_ISSUE_AAM_CERTIFICATE = "This is not the way to issue AAM certificate";
    public static final String AWKWARD_SSP = "That is an awkward ssp, please change ssp interworking interface addresses";
    public static final String SSP_NOT_EXIST = "Ssp with this instance id doesn't exist";
    public static final String SSP_INTERWARKING_INTERFACE_IN_USE = "Ssp exposed interworking interface already in use";
    public static final String SSP_EXISTS = "Ssp with this instance id already exists";
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    public static HttpStatus statusCode = HttpStatus.BAD_REQUEST;

    public SspManagementException() {
        super(errorMessage);
    }

    public SspManagementException(HttpStatus statusCode) {
        super(errorMessage);
        this.statusCode = statusCode;
    }

    public SspManagementException(String message, HttpStatus statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public SspManagementException(Throwable cause, HttpStatus statusCode) {
        super(cause);
        this.statusCode = statusCode;
    }

    public SspManagementException(String message, Throwable cause, HttpStatus statusCode) {
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
