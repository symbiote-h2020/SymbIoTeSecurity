package eu.h2020.symbiote.security.accesspolicies.common;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

public class UniversalAccessPolicyFactory {

    private UniversalAccessPolicyFactory() {
    }

    /**
     * Create the access policy from a {@link SingleTokenAccessPolicySpecifier SingleTokenAccessPolicySpecifier} or {@link CompositeAccessPolicySpecifier CompositeAccessPolicySpecifier} depending on {@link AccessPolicyType AccessPolicyType}.
     *
     * @param specifier the access policy specifier
     * @return the sample access policy
     * @throws InvalidArgumentsException in case of unknown AccessPolicyType
     */
    public static IAccessPolicy getAccessPolicy(IAccessPolicySpecifier specifier) throws InvalidArgumentsException {
        switch (specifier.getPolicyType()) {
            case CAP:
                return CompositeAccessPolicyFactory.getCompositeAccessPolicy((CompositeAccessPolicySpecifier) specifier);
            default:
                return SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy((SingleTokenAccessPolicySpecifier) specifier);
        }

    }
}
