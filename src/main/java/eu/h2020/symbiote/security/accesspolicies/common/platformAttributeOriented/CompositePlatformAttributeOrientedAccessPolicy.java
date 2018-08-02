package eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.AttributeOrientedAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import java.util.HashSet;
import java.util.Set;

/**
 * SymbIoTe Access Policies based on composite platform attribute-oriented access rules that needs to be satisfied by one or multiple Token issued by specific platforms:
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class CompositePlatformAttributeOrientedAccessPolicy implements IAccessPolicy {

    private final CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator policiesRelationOperator;
    private final Set<PlatformAttributeOrientedAccessPolicySpecifier> singlePlatformAttrOrientedAccessPolicies;
    private final Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> compositePlatformAttrOrientedAccessPolicies;


    /**
     * Creates a new access policy object
     */
    public CompositePlatformAttributeOrientedAccessPolicy(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator policiesRelationOperator, Set<PlatformAttributeOrientedAccessPolicySpecifier> singlePlatformAttrOrientedAccessPolicies, Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> compositePlatformAttrOrientedAccessPolicies) {
        this.policiesRelationOperator = policiesRelationOperator;
        this.singlePlatformAttrOrientedAccessPolicies = singlePlatformAttrOrientedAccessPolicies;
        this.compositePlatformAttrOrientedAccessPolicies = compositePlatformAttrOrientedAccessPolicies;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {
        Set<Token> returnTokensSet = new HashSet<>();
        switch (this.policiesRelationOperator) {
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
            if (this.singlePlatformAttrOrientedAccessPolicies != null) {
                requiredNumberOfValidPolicies += this.singlePlatformAttrOrientedAccessPolicies.size();
                for (PlatformAttributeOrientedAccessPolicySpecifier paoapSpecifier : this.singlePlatformAttrOrientedAccessPolicies) {
                    IAccessPolicy policy = AttributeOrientedAccessPolicyFactory.getPlatformAttributeOrientedAccessPolicy(paoapSpecifier);
                    Set<Token> validTokens = policy.isSatisfiedWith(authorizationTokens);
                    // if no tokens were found that satisfy access policy
                    if ((validTokens != null) && !validTokens.isEmpty()) {
                        returnTokensSet.addAll(validTokens);
                        satisfiedAccessPolicies++;
                    }
                }
            }

            if (this.compositePlatformAttrOrientedAccessPolicies != null) {
                requiredNumberOfValidPolicies += this.compositePlatformAttrOrientedAccessPolicies.size();
                for (CompositePlatformAttributeOrientedAccessPolicySpecifier cpaoapSpecifier : this.compositePlatformAttrOrientedAccessPolicies) {
                    IAccessPolicy policy = AttributeOrientedAccessPolicyFactory.getCompositePlatformAttributeOrientedAccessPolicy(cpaoapSpecifier);
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
            if (this.singlePlatformAttrOrientedAccessPolicies != null) {
                for (PlatformAttributeOrientedAccessPolicySpecifier paoapSpecifier : this.singlePlatformAttrOrientedAccessPolicies) {
                    IAccessPolicy policy = AttributeOrientedAccessPolicyFactory.getPlatformAttributeOrientedAccessPolicy(paoapSpecifier);
                    Set<Token> validTokens = policy.isSatisfiedWith(authorizationTokens);
                    // if at least one token was found that satisfies access policy
                    if ((validTokens != null) && !validTokens.isEmpty()) {
                        return validTokens;
                    }
                }
            }
            if (this.compositePlatformAttrOrientedAccessPolicies != null) {
                for (CompositePlatformAttributeOrientedAccessPolicySpecifier cpaoapSpecifier : this.compositePlatformAttrOrientedAccessPolicies) {
                    IAccessPolicy policy = AttributeOrientedAccessPolicyFactory.getCompositePlatformAttributeOrientedAccessPolicy(cpaoapSpecifier);
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
