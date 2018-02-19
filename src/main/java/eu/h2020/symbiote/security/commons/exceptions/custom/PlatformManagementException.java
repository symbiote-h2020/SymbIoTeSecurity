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

    public static final String errorMessage = "PLATFORM_MANAGEMENT_ERROR";
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    public static final String INVALID_OPERATION = "Invalid operation";
    public static final String USER_IS_NOT_A_PLATFORM_OWNER = "User is not a Platform Owner";
    public static final String WRONG_WAY_TO_ISSUE_AAM_CERTIFICATE = "This is not the way to issue AAM certificate";
    public static HttpStatus statusCode = HttpStatus.BAD_REQUEST;

    public static final String AWKWARD_PLATFORM = "That is an awkward platform, please change an instance id or platform interworking interface address";
    public static final String PLATFORM_NOT_EXIST = "Platform with this instance id doesn't exist";
    public static final String PLATFORM_INTERWARKING_INTERFACE_IN_USE = "Platform interworking interface already in use";
    public static final String PLATFORM_EXISTS = "Platform with this instance id already exists";
    public static final String NOT_OWNED_PLATFORM = "Platform Owner does not have rights to this platform.";

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
