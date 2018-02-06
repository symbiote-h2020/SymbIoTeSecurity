package eu.h2020.symbiote.security.accesspolicies.common;

/**
 * Enumeration for specifying the policyType of the access policy.
 *
 * @author Vasileios Glykantzis (ICOM)
 * @author Jakub Toczek (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public enum AccessPolicyType {
    /**
     * SingleLocalHomeTokenIdentityBasedAccessPolicy
     */
    SLHTIBAP,
    /**
     * SingleLocalHomeTokenAccessPolicy
     */
    SLHTAP,
    /**
     * SingleFederatedTokenAccessPolicy
     */
    SFTAP,
    /**
     * SingleTokenAccessPolicy
     */
    STAP,
    /**
     * ComponentHomeTokenAccessPolicy
     */
    CHTAP,
    /**
     * Public access policy
     */
    PUBLIC,
    /**
     * Composite access policy
     */
    CAP,
    /**
     * Attribute-oriented access policy
     */
    AOAP

}
