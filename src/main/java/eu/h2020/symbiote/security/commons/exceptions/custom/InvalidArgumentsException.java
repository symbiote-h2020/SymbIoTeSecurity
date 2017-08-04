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
 */
public class InvalidArgumentsException extends SecurityException {

    public final static String errorMessage = "ERR_INVALID_ARGUMENTS";
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    private final static HttpStatus statusCode = HttpStatus.BAD_REQUEST;

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
