package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when a validation operation in symbIoTe fails
 * The message contains value of @{@link ValidationStatus}
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class ValidationException extends SecurityException {

    private static final long serialVersionUID = SecurityConstants.serialVersionUID;

    public static final String VALIDATION_ERROR_OCCURRED = "Validation error occurred";
    public static final String USING_REVOKED_KEY = "Using revoked key";
    public static final String WRONG_DEPLOYMENT_ID = "Deployment id's mismatch";
    public static final String USER_NOT_FOUND_IN_DB = "User not found in db";
    public static final String ISSUING_FOREIGN_TOKEN_ERROR = "Someone tried issuing a foreign token using a home token";
    public static final String INVALID_TOKEN = "Invalid token";
    public static final String NO_RIGHTS_TO_TOKEN = "You have no rights to this token";
    public static final String FOREIGN_TOKEN_NOT_MATCH_REMOTE_HOME_TOKEN = "Foreign token is invalid and does not mach remote Home Token";
    public static final String CERTIFICATE_MISMATCH = "Core AAM certificate does not match certificate known to us, possibly malicious core";
    //todo review if status codes and change of parent are valid
    private static final String errorMessage = "VALIDATION_ERROR";
    private static final HttpStatus statusCode = HttpStatus.UNAUTHORIZED;

    public ValidationException(String validationStatus) {
        super(validationStatus);
    }
    public ValidationException(String validationStatus, Throwable cause) {
        super(validationStatus, cause);
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