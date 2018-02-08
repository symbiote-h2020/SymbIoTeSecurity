package eu.h2020.symbiote.security.commons.exceptions.custom;


import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.springframework.http.HttpStatus;

public class SecurityHandlerException extends SecurityException {
    private static final long serialVersionUID = 1L;
    public static final String AAM_CERTIFICATE_DIFFERENT_THAN_IN_KEYSTORE = "The home AAM's certificate changed during the component's runtime. If it was an expected change please please delete this component's keystore and restart it. Otherwise this situation is an Indicator of Compromise. This component ceases to work until relevant actions have been undertaken.";
    //todo verify if statuses are ok
    private static final String errorMessage = "SECURITY_HANDLER_ERROR";
    private static final HttpStatus statusCode = HttpStatus.UNAUTHORIZED;

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
