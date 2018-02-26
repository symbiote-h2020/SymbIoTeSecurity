package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when arguments a invalid or missing
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class InvalidArgumentsException extends SecurityException {

    public static final String errorMessage = "ERR_INVALID_ARGUMENTS";
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    public static final String MISSING_PLATFORM_AAM_URL = "Missing Platform AAM URL";
    public static final String MISSING_USERNAME_OR_PASSWORD = "Missing username or password";
    public static final String MISSING_INSTANCE_FRIENDLY_NAME = "Missing service instance's Friendly Name";
    public static final String MISSING_CREDENTIALS = "Missing credentials";
    public static final String REQUEST_IS_INCORRECTLY_BUILT = "Request is incorrectly built";
    public static final String COULD_NOT_CREATE_USER_WITH_GIVEN_USERNAME = "Could not create user with given Username";
    public static final String MISSING_RECOVERY_E_MAIL_OR_OAUTH_IDENTITY = "Missing recovery e-mail or OAuth identity";
    public static final String COMPONENT_NOT_EXIST = "Component doesn't exist in this platform";
    public static final String COMMON_NAME_IS_WRONG = "Common name is wrong";
    public static final String RULE_ID_ALREADY_EXISTS = "Rule with this id already exists";
    private static final HttpStatus statusCode = HttpStatus.BAD_REQUEST;
    public static final String MISSING_SITE_LOCAL_ADDRESS = "Exposed site-local address must be provided";
    public static final String NO_SSP_PREFIX = "Smart space identifier must start with 'SSP_' prefix.";
    public static final String GATEWAY_ADDRESS_SHOULD_START_WITH_HTTPS = "Gateway Address should start with https.";

    public InvalidArgumentsException() {
        super(errorMessage);
    }

    public InvalidArgumentsException(String message) {
        super(message);
    }

    public InvalidArgumentsException(Throwable cause) {
        super(cause);
    }

    public InvalidArgumentsException(String message, Throwable cause) {
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
