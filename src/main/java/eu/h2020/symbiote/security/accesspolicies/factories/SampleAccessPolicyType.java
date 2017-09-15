package eu.h2020.symbiote.security.accesspolicies.factories;

/**
 * Enumeration for specifying the type of the sample access policy.
 *
 * @author Vasileios Glykantzis (ICOM)
 */
public enum SampleAccessPolicyType {
    /**
     * SingleLocalHomeTokenAccessPolicy
     */
    SLHTAP,
    /**
     * SingleLocalHomeTokenIdentityBasedTokenAccessPolicy
     */
    SLHTIBTAP,
    /**
     * SingleTokenAccessPolicy
     */
    STAP,
    /**
     * Public access
     */
    PUBLIC;
}
