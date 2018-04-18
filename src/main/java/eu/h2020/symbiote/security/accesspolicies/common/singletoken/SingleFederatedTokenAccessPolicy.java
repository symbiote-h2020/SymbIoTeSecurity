package eu.h2020.symbiote.security.accesspolicies.common.singletoken;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;

import java.util.HashSet;
import java.util.Set;

/**
 * SymbIoTe Access Policy that needs to be satisfied by a single Token issued by the local platform:
 * - a HOME one for local users/apps that have claims required to access the resource OR
 * - a FOREIGN one issued in exchange for a HOME token from the federation members and containing the federation identifier claim
 * basically the same as @{@link SingleFederatedHomeTokenAccessPolicy} but requiring federation members to acquire local domain credentials
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class SingleFederatedTokenAccessPolicy implements IAccessPolicy {
    private final String homePlatformIdentifier;
    private final Set<String> federationMembers;
    private final String federationIdentifier;

    /**
     * Creates a new access policy object
     *
     * @param homePlatformIdentifier so that HOME tokens are properly identified
     *                               TODO add param required claims for home users
     * @param federationIdentifier   identifier of the federation
     * @param federationMembers      set containing federation members identifiers
     *
     */
    public SingleFederatedTokenAccessPolicy(Set<String> federationMembers, String homePlatformIdentifier, String federationIdentifier) throws
            InvalidArgumentsException {
        if (federationMembers == null
                || federationMembers.isEmpty()
                || homePlatformIdentifier == null
                || homePlatformIdentifier.isEmpty()
                || federationIdentifier == null
                || federationIdentifier.isEmpty()
                || !federationMembers.contains(homePlatformIdentifier))
            throw new InvalidArgumentsException("Missing federation definition contents required to build this policy type");
        this.homePlatformIdentifier = homePlatformIdentifier;
        this.federationMembers = federationMembers;
        this.federationIdentifier = federationIdentifier;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {
        // presume that none of the tokens could satisfy the policy
        Set<Token> validTokens = new HashSet<>();
        // trying to find token satisfying this policy
        for (Token token : authorizationTokens) {
            //verify if token is HOME ttyp and if token is issued by this platform
            if (token.getType().equals(Token.Type.HOME) // a local token
                    && token.getClaims().getIssuer().equals(homePlatformIdentifier)) { // issued by us
                // todo check required claims
                validTokens.add(token);
                return validTokens;
            }
            // a foreign token issued by member with the proper key should be processed for searching the federation id
            if (token.getType().equals(Token.Type.FOREIGN) // an exchanged token
                    && token.getClaims().getIssuer().equals(homePlatformIdentifier) // issued by the local service
                    && federationMembers.contains(token.getClaims().getSubject().split(CryptoHelper.FIELDS_DELIMITER)[1])) { // the federation still harbour the platform the client comes from
                for (String claimKey : token.getClaims().keySet()) {
                    if (claimKey.startsWith(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + SecurityConstants.FEDERATION_CLAIM_KEY_PREFIX))
                        // checking if federation claims have our needed id
                        if (token.getClaims().get(claimKey).toString().equals(federationIdentifier)) {
                            validTokens.add(token);
                            return validTokens;
                        }
                }
            }
        }
        return validTokens;
    }
}
