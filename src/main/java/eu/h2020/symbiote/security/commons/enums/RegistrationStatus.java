package eu.h2020.symbiote.security.commons.enums;

/**
 * Used to define the status of registration procedure
 * @author Maks Marcinowski(PSNC)
 */
public enum RegistrationStatus {

    /**
     * successful registration
     */
    OK,
    /**
     * user already registered
     */
    USERNAME_EXISTS,
    /**
     * platform already registered
     */
    PLATFORM_EXISTS,
    /**
     * when the registration procedure failed
     */
    ERROR
}
