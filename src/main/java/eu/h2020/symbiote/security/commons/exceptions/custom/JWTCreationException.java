package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when JWT token creation fails
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class JWTCreationException extends SecurityException {

    public static final String MISCONFIGURED_AAM_DEPLOYMENT_TYPE = "Misconfigured AAM deployment type";
    private final static String errorMessage = "UNABLE_CREATE_JWT_TOKEN";
    private final static HttpStatus statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
    private final static long serialVersionUID = SecurityConstants.serialVersionUID;
    public static final String SERVER_FAILED_USE_COUPON = "Server failed to use the coupon.";
    public static final String SERVER_FAILED_BUILD_COUPON = "Server failed to build the coupon.";

    public JWTCreationException() {
        super(errorMessage);
    }

    public JWTCreationException(String message) {
        super(message);
    }

    public JWTCreationException(Throwable cause) {
        super(cause);
    }

    public JWTCreationException(String message, Throwable cause) {
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