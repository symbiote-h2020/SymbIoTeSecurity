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
 * SymbIoTe Access Policy that needs to be satisfied by a single Token issued by component's local AAM for that component.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class ComponentHomeTokenAccessPolicy implements IAccessPolicy {

    private final String platformIdentifier;
    private final String componentId;
    private Map<String, String> requiredClaims = new HashMap<>();

    /**
     * Creates a new access policy object
     * @param platformIdentifier so that we make sure that the token was issued by the platform the components belongs to
     * @param componentId        the component identifier which should have access to the resource
     * @param requiredClaims     optional map with all other claims that need to be contained in a single token to satisfy the policy
     */
    public ComponentHomeTokenAccessPolicy(String platformIdentifier, String componentId, Map<String, String> requiredClaims) throws
            InvalidArgumentsException {
        if (platformIdentifier == null || platformIdentifier.isEmpty())
            throw new InvalidArgumentsException("Platform identifier must not be null/empty!");
        this.platformIdentifier = platformIdentifier;
        if (componentId == null || componentId.isEmpty())
            throw new InvalidArgumentsException("Component identifier must not be null/empty!");
        this.componentId = componentId;
        if (requiredClaims != null)
            this.requiredClaims = requiredClaims;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {
        Set<Token> validTokens = new HashSet<>();
        // presume that none of the tokens could satisfy the policy
        // trying to find token satisfying this policy
        for (Token token : authorizationTokens) {
            //verify if token
            if (token.getType().equals(Token.Type.HOME) // is HOME ttyp
                    && token.getClaims().getIssuer().equals(platformIdentifier) // is issued by this/local (platform) AAM
                    && token.getClaims().getSubject().equals(componentId) // for the given component
                    && isSatisfiedWith(token)) { // and if the token satisfies the general policy idea
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
