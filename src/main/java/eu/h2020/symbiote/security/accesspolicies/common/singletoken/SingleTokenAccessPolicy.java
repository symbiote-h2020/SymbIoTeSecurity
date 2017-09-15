package eu.h2020.symbiote.security.accesspolicies.common.singletoken;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.Token;

import java.util.HashMap;
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
    private Map<String, String> requiredClaims = new HashMap<>();

    /**
     * Creates a new access policy object
     *
     * @param requiredClaims map with all the claims that need to be contained in a single token to satisfy the
     *                       access policy
     */
    public SingleTokenAccessPolicy(Map<String, String> requiredClaims) {
        if (requiredClaims != null) this.requiredClaims = requiredClaims;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {
        // presume that none of the tokens could satisfy the policy
        Set<Token> validTokens = new HashSet<>();
        // trying to find a token satisfying this policy
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
        // empty access policy is satisfied by any token
        if (requiredClaims.isEmpty())
            return true;

        // need to verify that all the required claims are in the token
        for (Entry<String, String> requiredClaim : requiredClaims.entrySet()) {
            // try to find requiredClaim in token attributes
            String claimValue = (String) token.getClaims().get(requiredClaim.getKey());
            // missing claim causes failed authorization
            if (claimValue == null)
                return false;
            // wrong value of the claim also causes failed authorization
            if (!requiredClaim.getValue().equals(claimValue))
                return false;
        }
        // token passes the satisfaction procedure
        return true;
    }
}
