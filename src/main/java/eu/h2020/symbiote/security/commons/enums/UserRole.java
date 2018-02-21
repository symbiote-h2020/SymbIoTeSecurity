package eu.h2020.symbiote.security.commons.enums;

/**
 * Denotes what kind of role the user has in symbIoTe ecosystem
 */
public enum UserRole {
    /**
     * default symbIoTe's data consumer role
     */
    USER,
    /**
     * symbIoTe-enabled service's (platforms and ssps) owner account type, used to release administration attributes.
     */
    SERVICE_OWNER,
    /**
     * uninitialized value of this enum
     */
    NULL
}
