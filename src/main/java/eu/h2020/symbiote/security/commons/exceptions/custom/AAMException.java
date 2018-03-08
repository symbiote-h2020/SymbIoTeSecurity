package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when AAM fails to do some operation
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class AAMException extends SecurityException {

    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    public static final String NO_TOKEN_IN_RESPONSE = "Error occured. There is no token in response!";
    public static final String RESPONSE_IS_EMPTY = "Error occured. Response is empty!";
    public static final String DATABASE_INCONSISTENCY = "Error occured. Database inconsistency was detected!";
    public static final String SELECTED_CERTIFICATE_NOT_FOUND = "Selected certificate could not be found/retrieved";
    private static final String errorMessage = "AAM_SERVER_ERROR";
    private static final HttpStatus statusCode = HttpStatus.INTERNAL_SERVER_ERROR;

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