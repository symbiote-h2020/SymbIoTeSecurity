package eu.h2020.symbiote.security.commons.exceptions.custom;


import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

public class SecurityHandlerException extends SecurityException {
    private static final long serialVersionUID = 1L;
    //todo verify if statuses are ok
    private final static String errorMessage = "SECURITY_HANDLER_ERROR";
    private final static HttpStatus statusCode = HttpStatus.UNAUTHORIZED;

    public SecurityHandlerException(String message, Throwable cause) {
        super(message, cause);
    }

    public SecurityHandlerException(String message) {
        super(message);
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
