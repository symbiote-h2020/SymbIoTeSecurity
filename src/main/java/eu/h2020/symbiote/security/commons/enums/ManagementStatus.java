package eu.h2020.symbiote.security.commons.enums;

/**
 * Used to define the status of a user/platform management procedure
 * @author Maks Marcinowski(PSNC)
 */
public enum ManagementStatus {
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
