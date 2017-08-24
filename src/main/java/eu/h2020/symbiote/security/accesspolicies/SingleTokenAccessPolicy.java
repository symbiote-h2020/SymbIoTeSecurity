package eu.h2020.symbiote.security.accesspolicies;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;

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
    public boolean isSatisfiedWith(String deploymentId, Set<Token> authorizationTokens) {
        // trying to find token satisfying this policy
        // presume that none of the tokens could satisfy the policy
        boolean result = false;
        for (Token token : authorizationTokens) {
            if (!result) {
                //verify if token is HOME ttyp and if token is issued by this platform and if the token satisfies the policy
                if (token.getType().equals(Token.Type.HOME) && token.getClaims().getIssuer().equals(deploymentId) && isSatisfiedWith(token)) {
                    result = true;
                }
            }
        }


        return result;
    }

    private boolean isSatisfiedWith(Token token) {
        // need to verify that all the required claims are in the token
        if (requiredClaims != null) {
            for (Entry<String, String> requiredClaim : requiredClaims.entrySet()) {
                //support for IBAC
                if (requiredClaim.getKey().equals(SecurityConstants.SUB_NAME_TOKEN_TYPE)) {
                    return token.getClaims().getSubject() != null ? requiredClaim.getValue().equals(token.getClaims().getSubject()) : false;
                } else {
                    // try to find requiredClaim in token attributes
                    String claimValue = (String) token.getClaims().get(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + requiredClaim.getKey());
                    //Validate presence of the attribute and matching of required value
                    return claimValue != null ? requiredClaim.getValue().equals(claimValue) : false;
                }
            }
        }
        // token passes the satisfaction procedure
        return true;
    }
}
