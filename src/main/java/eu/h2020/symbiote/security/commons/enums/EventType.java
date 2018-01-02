package eu.h2020.symbiote.security.commons.enums;

public enum EventType {

    /**
     * Error during token validation occurred.
     */
    VALIDATION_FAILED,
    /**
     * Error during User Management occurred due to wrong credentials.
     */
    LOGIN_FAILED,
    /**
     * Error during token acquisition occurred.
     */
    ACQUISITION_FAILED,
    /**
     * used only in default constructor of the EventLog.
     */
    NULL,

}