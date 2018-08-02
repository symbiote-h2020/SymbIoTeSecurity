package eu.h2020.symbiote.security.accesspolicies.common;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.AttributeOrientedAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.AttributeOrientedAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented.PlatformAttributeOrientedAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented.PlatformAttributeOrientedAccessPolicySpecifier;
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

    /**
     * Create the access policy from a {@link PlatformAttributeOrientedAccessPolicySpecifier platformAttributeOrientedAccessPolicySpecifier}.
     *
     * @param specifier the access policy specifier
     * @return the sample access policy
     * @throws InvalidArgumentsException
     */
    public static IAccessPolicy getPlatformAttributeOrientedAccessPolicy(PlatformAttributeOrientedAccessPolicySpecifier specifier) throws
            InvalidArgumentsException {

        return new PlatformAttributeOrientedAccessPolicy(specifier.getPlatformIdentifier(), specifier.getAttrOrientedAccessPolicySpecifier().getAccessRules());

    }
}
