package eu.h2020.symbiote.security.commons.exceptions.custom;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when BTM fails to do some operation
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class BTMException extends SecurityException {

    public static final String NO_COUPON_IN_RESPONSE = "Error occured. There is no coupon in response!";
    public static final String RESPONSE_IS_EMPTY = "Error occured. Response is empty!";
    public static final String DATABASE_INCONSISTENT = "Error occured. Inconsistency of database was detected!";
    public static final String SELECTED_CERTIFICATE_NOT_FOUND = "Selected certificate could not be found/retrieved";
    private static final long serialVersionUID = SecurityConstants.serialVersionUID;
    private static final String errorMessage = "BTM_SERVER_ERROR";
    private static final HttpStatus statusCode = HttpStatus.INTERNAL_SERVER_ERROR;

    public BTMException() {
        super(errorMessage);
    }

    public BTMException(String message) {
        super(message);
    }

    public BTMException(Throwable cause) {
        super(cause);
    }

    public BTMException(String message, Throwable cause) {
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