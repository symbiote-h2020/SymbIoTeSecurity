package eu.h2020.symbiote.security.accesspolicies.common;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.multipleDomain.MultipleDomainAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.multipleDomain.MultipleDomainAndOperatedAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.multipleDomain.MultipleDomainOrOperatedAccessPolicy;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

/**
 * Factory for producing sample multi domain access policies.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class MultipleDomainAccessPolicyFactory {

    private MultipleDomainAccessPolicyFactory() {
    }

    /**
     * Create the access policy from a {@link eu.h2020.symbiote.security.accesspolicies.common.multipleDomain.MultipleDomainAccessPolicySpecifier MultipleDomainAccessPolicySpecifier}.
     *
     * @param specifier the access policy specifier
     * @return the sample access policy
     * @throws InvalidArgumentsException
     */
    public static IAccessPolicy getMultipleDomainAccessPolicy(MultipleDomainAccessPolicySpecifier specifier) throws
            InvalidArgumentsException {

        switch (specifier.getRelationOperator()) {
            case AND:
                return new MultipleDomainAndOperatedAccessPolicy(specifier.getAccessPolicies());
            case OR:
                return new MultipleDomainOrOperatedAccessPolicy(specifier.getAccessPolicies());
            default:
                throw new InvalidArgumentsException("The type of the access policy operator was not recognized");
        }
    }
}
