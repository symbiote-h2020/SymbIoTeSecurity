package eu.h2020.symbiote.security.commons.enums;

/**
 * Describes user account status
 */
public enum AccountStatus {
    /**
     * for newly created accounts which need to be activated
     */
    NEW,
    /**
     * an account which creation was confirmed using e-mail or was unlocked by password reset
     */
    ACTIVE,
    /**
     * account which was blocked due to suspicious activity
     */
    BLOCKED
}