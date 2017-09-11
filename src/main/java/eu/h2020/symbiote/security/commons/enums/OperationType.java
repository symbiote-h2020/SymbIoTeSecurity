package eu.h2020.symbiote.security.commons.enums;

public enum OperationType {
    /**
     * creating actor
     */
    CREATE,
    /**
     * updating actor
     */
    UPDATE,
    /**
     * updating actors attributes
     */
    ATTRIBUTES_UPDATE,
    /**
     * deleting actor
     */
    DELETE,
    /**
     * force updating actor (used while resetting password)
     */
    FORCE_UPDATE,
    /**
     * reading actor's details
     */
    READ
}
