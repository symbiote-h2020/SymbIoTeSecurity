package eu.h2020.symbiote.security.accesspolicies;

import eu.h2020.symbiote.security.commons.Token;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * SymbIoTe Access Policy that needs to be satisfied by a single Token
 *
 * @author Mikołaj Dobski (PSNC)
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
    public boolean isSatisfiedWith(List<Token> authorizationTokens) {
        // trying to find token satisfying this policy
        for (Token token : authorizationTokens) {
            if (isSatisfiedWith(token))
                return true; // one of the tokens satisfied the policy

        }
        // none of the tokens could satisfy the policy
        return false;
    }

    private boolean isSatisfiedWith(Token token) {
        // need to verify that all the required claims are in the token
        for (Entry<String, String> requiredClaim : requiredClaims.entrySet()) {
            // try to find requiredClaim in token
            String claimValue = (String) token.getClaims().get(requiredClaim.getKey());
            if (claimValue == null)
                return false; // the token doesn't contain the required requiredClaim
            // checking the requiredClaim value
            if (!claimValue.equals(requiredClaim.getValue()))
                return false; // the token doesn't contain required value of that requiredClaim
        }
        // token passes the satisfaction procedure
        return true;
    }
}
