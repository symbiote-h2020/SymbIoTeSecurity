package eu.h2020.symbiote.security.exceptions.custom;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when username and/or password credentials are missing during login procedure
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class MissingArgumentsException extends SecurityException {

    public final static String errorMessage = "ERR_MISSING_ARGUMENTS";
    private static final long serialVersionUID = AAMConstants.serialVersionUID;
    private final static HttpStatus statusCode = HttpStatus.BAD_REQUEST;

    public MissingArgumentsException() {
        super(errorMessage);
    }

    public MissingArgumentsException(String message) {
        super(message);
    }

    public MissingArgumentsException(Throwable cause) {
        super(cause);
    }

    public MissingArgumentsException(String message, Throwable cause) {
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
