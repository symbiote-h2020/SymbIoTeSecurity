package eu.h2020.symbiote.security.exceptions.custom;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when platform is already present in DB during registration procedure
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class ExistingPlatformException extends SecurityException {

    public final static String errorMessage = "PLATFORM_ALREADY_REGISTERED";
    private static final long serialVersionUID = AAMConstants.serialVersionUID;
    private final static HttpStatus statusCode = HttpStatus.BAD_REQUEST;

    public ExistingPlatformException() {
        super(errorMessage);
    }

    public ExistingPlatformException(String message) {
        super(message);
    }

    public ExistingPlatformException(Throwable cause) {
        super(cause);
    }

    public ExistingPlatformException(String message, Throwable cause) {
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
