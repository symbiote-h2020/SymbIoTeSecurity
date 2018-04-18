package eu.h2020.symbiote.security.accesspolicies.common.singletoken;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * SymbIoTe Access Policy that needs to be satisfied by a single Home Token:
 * - issued by one of the federation members and containing the federation identifier claim
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class SingleFederatedHomeTokenAccessPolicy implements IAccessPolicy {
    private final Set<String> federationMembers;
    private final String federationIdentifier;
    private final String localPlatformIdentifier;
    private final Map<String, String> requiredClaims;

    /**
     * Creates a new access policy object
     *
     * @param federationMembers    set containing federation members identifiers
     * @param federationIdentifier identifier of the federation
     * @param localPlatformIdentifier identifier of the local platform to identify local Home Token
     * @param requiredClaims        map of claims that should appear in local Home Token to pass the policy
     */
    public SingleFederatedHomeTokenAccessPolicy(Set<String> federationMembers, String federationIdentifier, String localPlatformIdentifier, Map<String, String> requiredClaims) throws
            InvalidArgumentsException {
        if (federationMembers == null
                || federationMembers.isEmpty()
                || federationIdentifier == null
                || federationIdentifier.isEmpty())
            throw new InvalidArgumentsException("Missing federation definition contents required to build this policy type");
        this.federationMembers = federationMembers;
        this.federationIdentifier = federationIdentifier;
        this.localPlatformIdentifier = localPlatformIdentifier;
        this.requiredClaims = requiredClaims;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {
        // presume that none of the tokens could satisfy the policy
        Set<Token> validTokens = new HashSet<>();
        // trying to find token satisfying this policy
        for (Token token : authorizationTokens) {

            if (token.getType().equals(Token.Type.HOME)
                    && token.getClaims().getIssuer().equals(localPlatformIdentifier)
                    && isSatisfiedWith(token)) {
                validTokens.add(token);
                return validTokens;
            }
            // a Home token issued by member with the proper key should be processed for searching the federation id
            if (token.getType().equals(Token.Type.HOME)
                    && !token.getClaims().getIssuer().equals(localPlatformIdentifier)
                    && federationMembers.contains(token.getClaims().getIssuer())) {
                Set<String> federationIdentifierClaims = new HashSet<>();
                for (String claimKey : token.getClaims().keySet()) {
                    if (claimKey.startsWith(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + SecurityConstants.FEDERATION_CLAIM_KEY_PREFIX))
                        federationIdentifierClaims.add(token.getClaims().get(claimKey).toString());
                }
                // checking if federation claims have our needed id
                if (federationIdentifierClaims.contains(federationIdentifier)) {
                    validTokens.add(token);
                    return validTokens;
                }
            }
        }

        return validTokens;
    }

    private boolean isSatisfiedWith(Token token) {
        // empty access policy is satisfied by any token
        if (requiredClaims.isEmpty())
            return true;

        // need to verify that all the required claims are in the token
        for (Map.Entry<String, String> requiredClaim : requiredClaims.entrySet()) {
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
