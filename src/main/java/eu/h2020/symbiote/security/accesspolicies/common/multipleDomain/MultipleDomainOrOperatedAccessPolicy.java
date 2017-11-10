package eu.h2020.symbiote.security.accesspolicies.common.multipleDomain;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import java.util.HashSet;
import java.util.Set;

/**
 * SymbIoTe Access Policies bound with OR operator that needs to be satisfied by one or multiple Token:
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class MultipleDomainOrOperatedAccessPolicy implements IAccessPolicy {

    private final Set<IAccessPolicy> accessPolicies;

    /**
     * Creates a new access policy object
     *
     * @param accessPolicies Access policies that will be validated
     */
    public MultipleDomainOrOperatedAccessPolicy(Set<IAccessPolicy> accessPolicies) throws
            InvalidArgumentsException {

        this.accessPolicies = accessPolicies;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {
        // presume that none of the tokens could satisfy the policy
        Set<Token> returnTokensSet = new HashSet<>();

        for (IAccessPolicy policy : this.accessPolicies) {
            Set<Token> validTokens = policy.isSatisfiedWith(authorizationTokens);
            // if at least one token was found that satisfies access policy
            if ((validTokens != null) && !validTokens.isEmpty()) {
                returnTokensSet.addAll(validTokens);
            }
        }

        return returnTokensSet;
    }
}
