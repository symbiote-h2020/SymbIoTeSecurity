package eu.h2020.symbiote.security.accesspolicies.common;

/**
 * Interface that all access policies specifiers in SymbIoTe need to implement
 *
 * @author Jakub Toczek (PSNC)
 */
public interface IAccessPolicySpecifier {
    /**
     * @return AccessPolicyType that describe access policy specifier
     */
    AccessPolicyType getPolicyType();
}
