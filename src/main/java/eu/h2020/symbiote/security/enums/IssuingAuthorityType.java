package eu.h2020.symbiote.security.enums;

/**
 * Used to define the {eu.h2020.symbiote.security.AuthenticationAuthorizationManager} deployment type:
 * CoreAAM,
 * PlatformAAM
 * or NullAAM (for tests)
 *
 * TODO @Mikołaj introduce the new enum TokenType (HOME,FOREIGN,GUEST) and fix usage of this constant in the AAM
 * codes only
 *
 * @author Mikołaj Dobski (PSNC)
 */
public enum IssuingAuthorityType {
    /**
     * Core AAM
     */
    CORE,
    /**
     * Platform AAM
     */
    PLATFORM,
    /**
     * uninitialised value of this enum, useful for TestAAM
     */
    NULL
}
