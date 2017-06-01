package eu.h2020.symbiote.security.exceptions.custom;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;

/**
 * Custom exception thrown when a validation operation in symbIoTe fails
 * The message contains value of @{@link eu.h2020.symbiote.security.enums.ValidationStatus}
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class ValidationException extends SecurityHandlerException {

    private static final long serialVersionUID = AAMConstants.serialVersionUID;

    public ValidationException(String validationStatus) {
        super(validationStatus);
    }

    public ValidationException(String validationStatus, Throwable cause) {
        super(validationStatus, cause);
    }
}