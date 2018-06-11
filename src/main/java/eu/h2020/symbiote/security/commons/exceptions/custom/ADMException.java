package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when Anomaly Detection Module fails to do some operation
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class ADMException extends SecurityException {

    public static final String ADM_NOT_AVAILABLE = "Error occured. Anomaly Detection Module is not available";
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    private static final String errorMessage = "ADM_SERVER_ERROR";
    private static final HttpStatus statusCode = HttpStatus.INTERNAL_SERVER_ERROR;

    public ADMException() {
        super(errorMessage);
    }

    public ADMException(String message) {
        super(message);
    }

    public ADMException(Throwable cause) {
        super(cause);
    }

    public ADMException(String message, Throwable cause) {
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