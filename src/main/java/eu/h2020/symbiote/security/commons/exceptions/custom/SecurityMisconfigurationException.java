package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when the AAM is misconfigured and attempted to run in this state
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class SecurityMisconfigurationException extends SecurityException {

    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    public static final String GENERIC_README_NOTICE = "Please check relevant for your deployment Symbiote Core/Cloud/Enabler/SmartSpace and/or AAM repository readme for instructions on how to configure your AAM.";
    public static final String AAM_OWNER_USER_ALREADY_REGISTERED = "AAM owner user already registered in database... Either delete that user or choose a different administrator username";
    public static final String AAM_HAS_NO_FEDERATIONS_DEFINED = "AAM has no foreign rules defined";
    public static final String AAM_PRIVATE_KEY_NOT_FOUND_IN_GIVEN_CONFIGURATION = "Can't find AAM private key using the given configuration.";
    public static final String CONFIGURATION_POINTS_TO_WRONG_CERTIFICATE = "Configuration points to a certificate that doesn't match the symbiote requirements.";
    private static final String errorMessage = "AAM_MISCONFIGURED";
    private static final HttpStatus statusCode = HttpStatus.INTERNAL_SERVER_ERROR;

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
