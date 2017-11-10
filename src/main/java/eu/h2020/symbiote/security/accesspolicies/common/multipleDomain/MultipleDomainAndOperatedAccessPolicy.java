package eu.h2020.symbiote.security.accesspolicies.common.multipleDomain;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import java.util.HashSet;
import java.util.Set;

/**
 * SymbIoTe Access Policies bound with AND operator that needs to be satisfied by one or multiple Token:
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class MultipleDomainAndOperatedAccessPolicy implements IAccessPolicy {
    private final Set<IAccessPolicy> accessPolicies;

    /**
     * Creates a new access policy object
     *
     * @param accessPolicies Access policies that will be validated
     */
    public MultipleDomainAndOperatedAccessPolicy(Set<IAccessPolicy> accessPolicies) throws
            InvalidArgumentsException {
        this.accessPolicies = accessPolicies;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {

        Set<Token> returnTokensSet = new HashSet<>();
        int satisfiedAccessPolicies = 0;

        for (IAccessPolicy policy : this.accessPolicies) {
            Set<Token> validTokens = policy.isSatisfiedWith(authorizationTokens);
            // if no tokens were found that satisfy access policy
            if ((validTokens != null) && !validTokens.isEmpty()) {
                returnTokensSet.addAll(validTokens);
                satisfiedAccessPolicies++;
            }
        }
        //Not all access policies are satisfied => access is forbidden
        if (satisfiedAccessPolicies < this.accessPolicies.size()) {
            //return empty set to signal failed validation of AP
            returnTokensSet.clear();
        }
        return returnTokensSet;
    }
}
