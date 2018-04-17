package eu.h2020.symbiote.security.accesspolicies.common.singletoken;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import java.util.HashSet;
import java.util.Set;

/**
 * SymbIoTe Access Policy that needs to be satisfied by a single Home Token:
 * - issued by one of the federation members and containing the federation identifier claim
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class FederatedResourceAccessPolicyUsingSingleHomeToken implements IAccessPolicy {
    private final Set<String> federationMembers;
    private final String federationIdentifier;

    /**
     * Creates a new access policy object
     *
     * @param federationIdentifier identifier of the federation
     * @param federationMembers    set containing federation members identifiers
     */
    public FederatedResourceAccessPolicyUsingSingleHomeToken(Set<String> federationMembers, String federationIdentifier) throws
            InvalidArgumentsException {
        if (federationMembers == null
                || federationMembers.isEmpty()
                || federationIdentifier == null
                || federationIdentifier.isEmpty())
            throw new InvalidArgumentsException("Missing federation definition contents required to build this policy type");
        this.federationMembers = federationMembers;
        this.federationIdentifier = federationIdentifier;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {
        // presume that none of the tokens could satisfy the policy
        Set<Token> validTokens = new HashSet<>();
        // trying to find token satisfying this policy
        for (Token token : authorizationTokens) {
            // a Home token issued by member with the proper key should be processed for searching the federation id
            if (token.getType().equals(Token.Type.HOME) && federationMembers.contains(token.getClaims().getIssuer())) {
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
}
