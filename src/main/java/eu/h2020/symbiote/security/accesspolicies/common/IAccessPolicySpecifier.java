package eu.h2020.symbiote.security.accesspolicies.common;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * Interface that all access policies specifiers in SymbIoTe need to implement
 *
 * @author Jakub Toczek (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@JsonDeserialize(using = AccessPolicyJSONDeserializer.class)
public interface IAccessPolicySpecifier {
    /**
     * @return AccessPolicyType that describe access policy specifier
     */
    AccessPolicyType getPolicyType();
}
