package eu.h2020.symbiote.security.accesspolicies;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;

import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * SymbIoTe Access Policy that needs to be satisfied by a single Token
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class SingleTokenAccessPolicy implements IAccessPolicy {
    private Map<String, String> requiredClaims;

    /**
     * Creates a new access policy object
     *
     * @param requiredClaims map with all the claims that need to be contained in a single token to satisfy the
     *                       access policy
     */
    public SingleTokenAccessPolicy(Map<String, String> requiredClaims) {
        this.requiredClaims = requiredClaims;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {
        // trying to find token satisfying this policy
        // presume that none of the tokens could satisfy the policy
        Set<Token> validTokens = new HashSet<>();
        for (Token token : authorizationTokens) {
            //verify if token satisfies the policy
            if (isSatisfiedWith(token)) {
                validTokens.add(token);
                return validTokens;
            }
        }
        return validTokens;
    }

    private boolean isSatisfiedWith(Token token) {
        // need to verify that all the required claims are in the token
        if (requiredClaims != null) {
            for (Entry<String, String> requiredClaim : requiredClaims.entrySet()) {
                // try to find requiredClaim in token attributes
                String claimValue = (String) token.getClaims().get(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + requiredClaim.getKey());
                //Validate presence of the attribute and matching of required value
                // TODO review so that is covers all required attributes!
                return claimValue != null ? requiredClaim.getValue().equals(claimValue) : false;
            }
        }

        // token passes the satisfaction procedure
        return true;
    }
}
