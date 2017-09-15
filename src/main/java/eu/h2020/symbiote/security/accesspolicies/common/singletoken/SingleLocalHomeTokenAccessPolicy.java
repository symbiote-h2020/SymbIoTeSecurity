package eu.h2020.symbiote.security.accesspolicies.common.singletoken;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * SymbIoTe Access Policy that needs to be satisfied by a single Token issued by local AAM
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class SingleLocalHomeTokenAccessPolicy implements IAccessPolicy {
    private final String platformIdentifier;
    private Map<String, String> requiredClaims = new HashMap<>();

    /**
     * Creates a new access policy object
     *
     * @param platformIdentifier so that HOME tokens are properly identified
     * @param requiredClaims     map with all the claims that need to be contained in a single token to satisfy the
     */
    public SingleLocalHomeTokenAccessPolicy(String platformIdentifier, Map<String, String> requiredClaims) throws
            InvalidArgumentsException {
        if (platformIdentifier == null || platformIdentifier.isEmpty())
            throw new InvalidArgumentsException("Platform identifier must not be null/empty!");
        this.platformIdentifier = platformIdentifier;
        if (requiredClaims != null)
            this.requiredClaims = requiredClaims;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {
        // presume that none of the tokens could satisfy the policy
        Set<Token> validTokens = new HashSet<>();
        // trying to find token satisfying this policy
        for (Token token : authorizationTokens) {
            //verify if token is HOME ttyp and if token is issued by this platform and if the token satisfies the general policy idea
            if (token.getType().equals(Token.Type.HOME) && token.getClaims().getIssuer().equals(platformIdentifier) && isSatisfiedWith(token)) {
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
