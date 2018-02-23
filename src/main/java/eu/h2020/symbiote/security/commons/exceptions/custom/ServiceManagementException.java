package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when platform or smartSpace management request fails
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Jakub Toczek (PSNC)
 */
public class ServiceManagementException extends SecurityException {

    public static final String errorMessage = "SERVICE_MANAGEMENT_ERROR";
    public static final String INVALID_OPERATION = "Invalid operation";
    public static final String USER_IS_NOT_A_SERVICE_OWNER = "User is not a Service Owner";
    public static final String WRONG_WAY_TO_ISSUE_AAM_CERTIFICATE = "This is not the way to issue AAM certificate";
    public static final String NO_RIGHTS = "User has no rights to this service. Check user's role and owned services.";
    public static final String AWKWARD_SERVICE = "That is an awkward service, please change an instance id or interworking interface address";
    public static final String SERVICE_NOT_EXIST = "Service with this instance id doesn't exist";
    // TODO rename to match the gateway / II address and/or the site-local address
    public static final String SERVICE_INTERWORKING_INTERFACE_IN_USE = "Service exposed interworking interface already in use";
    public static final String SERVICE_EXISTS = "Service with this instance id already exists";
    public static final String NOT_OWNED_SERVICE = "Service Owner does not have rights to this service.";
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    public static HttpStatus statusCode = HttpStatus.BAD_REQUEST;

    public ServiceManagementException() {
        super(errorMessage);
    }

    public ServiceManagementException(HttpStatus statusCode) {
        super(errorMessage);
        ServiceManagementException.statusCode = statusCode;
    }

    public ServiceManagementException(String message, HttpStatus statusCode) {
        super(message);
        ServiceManagementException.statusCode = statusCode;
    }

    public ServiceManagementException(Throwable cause, HttpStatus statusCode) {
        super(cause);
        ServiceManagementException.statusCode = statusCode;
    }

    public ServiceManagementException(String message, Throwable cause, HttpStatus statusCode) {
        super(message, cause);
        ServiceManagementException.statusCode = statusCode;
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
