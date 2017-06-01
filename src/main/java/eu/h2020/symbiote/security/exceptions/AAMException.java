package eu.h2020.symbiote.security.exceptions;

import eu.h2020.symbiote.security.constants.AAMConstants;
import org.springframework.http.HttpStatus;

/**
 * Abstract class implemented by custom exceptions in AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public abstract class AAMException extends Exception {

    public static final long serialVersionUID = AAMConstants.serialVersionUID;

    public AAMException(String message) {
        super(message);
    }

    public AAMException(Throwable cause) {
        super(cause);
    }

    public AAMException(String message, Throwable cause) {
        super(message, cause);
    }

    public abstract HttpStatus getStatusCode();

    public abstract String getErrorMessage();

}