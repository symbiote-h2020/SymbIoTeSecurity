package eu.h2020.symbiote.security.exceptions;

import eu.h2020.symbiote.security.constants.AAMConstants;
import org.springframework.http.HttpStatus;

/**
 * Abstract class implemented by custom exceptions in AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public abstract class SecurityException extends Exception {

    public static final long serialVersionUID = AAMConstants.serialVersionUID;

    public SecurityException(String message) {
        super(message);
    }

    public SecurityException(Throwable cause) {
        super(cause);
    }

    public SecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public abstract HttpStatus getStatusCode();

    public abstract String getErrorMessage();

}