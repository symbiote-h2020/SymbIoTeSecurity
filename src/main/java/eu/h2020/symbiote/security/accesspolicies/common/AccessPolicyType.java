package eu.h2020.symbiote.security.accesspolicies.common;

/**
 * Enumeration for specifying the policyType of the access policy.
 *
 * @author Vasileios Glykantzis (ICOM)
 * @author Jakub Toczek (PSNC)
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
     * FederatedResourceAccessPolicyUsingSingleForeignOrLocalHomeToken
     */
    FRAPUSFOLHT,
    /**
     * FederatedResourceAccessPolicyUsingSingleHomeToken
     */
    FRAPUSHT,
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
    CAP

}
