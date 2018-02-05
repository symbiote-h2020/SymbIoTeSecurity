package eu.h2020.symbiote.security.accesspolicies.common;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

/**
 * Factory for producing sample composite access policies.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class CompositeAccessPolicyFactory {

    private CompositeAccessPolicyFactory() {
    }

    /**
     * Create the access policy from a {@link eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicySpecifier CompositeAccessPolicySpecifier}.
     *
     * @param specifier the access policy specifier
     * @return the sample access policy
     * @throws InvalidArgumentsException
     */
    public static IAccessPolicy getCompositeAccessPolicy(CompositeAccessPolicySpecifier specifier) throws
            InvalidArgumentsException {

        return new CompositeAccessPolicy(specifier.getSingleTokenAccessPolicySpecifiers(), specifier.getCompositeAccessPolicySpecifiers(), specifier.getRelationOperator());

    }
}
