package eu.h2020.symbiote.security.accesspolicies.common.composite;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.CompositeAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import java.util.HashSet;
import java.util.Set;

/**
 * SymbIoTe Access Policies bound with logical operator that needs to be satisfied by one or multiple Token:
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class CompositeAccessPolicy implements IAccessPolicy {
    private final Set<SingleTokenAccessPolicySpecifier> singleTokenAccessPolicies;
    private final Set<CompositeAccessPolicySpecifier> compositeAccessPolicies;
    private final CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator logicalOperator;
    /**
     * Creates a new access policy object
     *
     * @param singleTokenAccessPolicies Access policies that will be validated
     */
    public CompositeAccessPolicy(Set<SingleTokenAccessPolicySpecifier> singleTokenAccessPolicies, Set<CompositeAccessPolicySpecifier> compositeAccessPolicies, CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator logicalOperator) throws
            InvalidArgumentsException {
        this.singleTokenAccessPolicies = singleTokenAccessPolicies;
        this.compositeAccessPolicies = compositeAccessPolicies;
        this.logicalOperator = logicalOperator;
    }

    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {

        Set<Token> returnTokensSet = new HashSet<>();
        switch (this.logicalOperator) {
            case AND:
                returnTokensSet = validateAndOperatorPolicy(authorizationTokens);
                break;
            case OR:
                returnTokensSet = validateOrOperatorPolicy(authorizationTokens);
                break;
            default:
                break;
        }
        return returnTokensSet;
    }

    private Set<Token> validateAndOperatorPolicy(Set<Token> authorizationTokens) {
        Set<Token> returnTokensSet = new HashSet<>();
        int satisfiedAccessPolicies = 0;
        int requiredNumberOfValidPolicies = 0;
        try {
            if (this.singleTokenAccessPolicies != null) {
                requiredNumberOfValidPolicies += this.singleTokenAccessPolicies.size();
                for (SingleTokenAccessPolicySpecifier stapSpecifier : this.singleTokenAccessPolicies) {
                    IAccessPolicy policy = SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(stapSpecifier);
                    Set<Token> validTokens = policy.isSatisfiedWith(authorizationTokens);
                    // if no tokens were found that satisfy access policy
                    if ((validTokens != null) && !validTokens.isEmpty()) {
                        returnTokensSet.addAll(validTokens);
                        satisfiedAccessPolicies++;
                    }
                }
            }

            if (this.compositeAccessPolicies != null) {
                requiredNumberOfValidPolicies += this.compositeAccessPolicies.size();
                for (CompositeAccessPolicySpecifier capSpecifier : this.compositeAccessPolicies) {
                    IAccessPolicy policy = CompositeAccessPolicyFactory.getCompositeAccessPolicy(capSpecifier);
                    Set<Token> validTokens = policy.isSatisfiedWith(authorizationTokens);
                    // if no tokens were found that satisfy access policy
                    if ((validTokens != null) && !validTokens.isEmpty()) {
                        returnTokensSet.addAll(validTokens);
                        satisfiedAccessPolicies++;
                    }
                }
            }

            //Not all access policies are satisfied => access is forbidden
            if (satisfiedAccessPolicies < requiredNumberOfValidPolicies) {
                //return empty set to signal failed validation of AP
                returnTokensSet.clear();
            }

        } catch (InvalidArgumentsException e) {
            //If any of the access policies is malformed, deny access
            returnTokensSet.clear();
        }

        return returnTokensSet;
    }

    private Set<Token> validateOrOperatorPolicy(Set<Token> authorizationTokens) {
        // presume that none of the tokens could satisfy the policy
        Set<Token> returnTokensSet = new HashSet<>();

        try {
            if (this.singleTokenAccessPolicies != null) {
                for (SingleTokenAccessPolicySpecifier stapSpecifier : this.singleTokenAccessPolicies) {
                    IAccessPolicy policy = SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(stapSpecifier);
                    Set<Token> validTokens = policy.isSatisfiedWith(authorizationTokens);
                    // if at least one token was found that satisfies access policy
                    if ((validTokens != null) && !validTokens.isEmpty()) {
                        return validTokens;
                    }
                }
            }
            if (this.compositeAccessPolicies != null) {
                for (CompositeAccessPolicySpecifier capSpecifier : this.compositeAccessPolicies) {
                    IAccessPolicy policy = CompositeAccessPolicyFactory.getCompositeAccessPolicy(capSpecifier);
                    Set<Token> validTokens = policy.isSatisfiedWith(authorizationTokens);
                    // if at least one token was found that satisfies access policy
                    if ((validTokens != null) && !validTokens.isEmpty()) {
                        return validTokens;
                    }
                }
            }

        } catch (InvalidArgumentsException e) {
            //If any of the access policies is malformed, deny access
            returnTokensSet.clear();
        }

        return returnTokensSet;
    }
}
