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

    //todo review if status codes and change of parent are valid
    private final static String errorMessage = "VALIDATION_ERROR";
    private final static HttpStatus statusCode = HttpStatus.UNAUTHORIZED;
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