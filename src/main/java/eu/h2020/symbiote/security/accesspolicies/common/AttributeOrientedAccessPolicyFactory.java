package eu.h2020.symbiote.security.accesspolicies.common;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.AttributeOrientedAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.AttributeOrientedAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

/**
 * Factory for producing sample attribute-oriented access policies.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class AttributeOrientedAccessPolicyFactory {

    private AttributeOrientedAccessPolicyFactory() {
    }

    /**
     * Create the access policy from a {@link eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.AttributeOrientedAccessPolicySpecifier AttributeOrientedAccessPolicySpecifier}.
     *
     * @param specifier the access policy specifier
     * @return the sample access policy
     * @throws InvalidArgumentsException
     */
    public static IAccessPolicy getAttributeOrientedAccessPolicy(AttributeOrientedAccessPolicySpecifier specifier) throws
            InvalidArgumentsException {

        return new AttributeOrientedAccessPolicy(specifier.getAccessRules());

    }
}
