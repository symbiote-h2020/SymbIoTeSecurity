package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when AAM fails to do some operation
 *
 * @author Mikolaj Dobski (PSNC)
 */
public class AAMException extends SecurityException {

    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    private final static String errorMessage = "AAM_SERVER_ERROR";
    private final static HttpStatus statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
    public static final String SELECTED_CERTIFICATE_NOT_FOUND = "Selected certificate could not be found/retrieved";

    public AAMException() {
        super(errorMessage);
    }

    public AAMException(String message) {
        super(message);
    }

    public AAMException(Throwable cause) {
        super(cause);
    }

    public AAMException(String message, Throwable cause) {
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