package eu.h2020.symbiote.security.accesspolicies.common.singletoken;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * SymbIoTe Access Policy that needs to be satisfied by a single Token:
 * - a HOME one issued by the local AAM for local users/apps that have claims required to access the resource OR
 * - a FOREIGN one issued by the local AAM in exchange for a HOME token from the federation members and containing the federation identifier claim OR
 * - (if requireAllLocalTokens== false) a HOME one issued by one of the federation members and containing the federation identifier claim
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class SingleFederatedTokenAccessPolicy implements IAccessPolicy {
    private final String localPlatformIdentifier;
    private final Set<String> federationMembers;
    private final String federationIdentifier;
    private final Map<String, String> requiredClaims;
    private final boolean requireAllLocalTokens;

    /**
     * Creates a new access policy object
     *
     * @param federationIdentifier      identifier of the federation
     * @param federationMembers         set containing federation members identifiers
     * @param localPlatformIdentifier   so that local HOME Tokens are properly identified
     * @param requiredClaims            map of claims that should appear in local Home Token to pass the policy
     * @param doesRequireAllLocalTokens requires exchange of platform Home Tokens to FOREIGN Token issued by local AAM with proper claims to pass the policy
     */
    public SingleFederatedTokenAccessPolicy(String federationIdentifier,
                                            Set<String> federationMembers, String localPlatformIdentifier, Map<String, String> requiredClaims, boolean doesRequireAllLocalTokens) throws
            InvalidArgumentsException {
        if (federationMembers == null
                || federationMembers.isEmpty()
                || localPlatformIdentifier == null
                || localPlatformIdentifier.isEmpty()
                || federationIdentifier == null
                || federationIdentifier.isEmpty()
                || !federationMembers.contains(localPlatformIdentifier))
            throw new InvalidArgumentsException("Missing federation definition contents required to build this policy type");
        this.localPlatformIdentifier = localPlatformIdentifier;
        this.federationMembers = federationMembers;
        this.federationIdentifier = federationIdentifier;
        this.requiredClaims = requiredClaims;
        this.requireAllLocalTokens = doesRequireAllLocalTokens;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {
        // presume that none of the tokens could satisfy the policy
        Set<Token> validTokens = new HashSet<>();
        // trying to find token satisfying this policy
        for (Token token : authorizationTokens) {
            //verify if token is HOME ttyp and if token is issued by this platform
            if (token.getType().equals(Token.Type.HOME) // a Home Token
                    && token.getClaims().getIssuer().equals(localPlatformIdentifier) // issued by us
                    && isSatisfiedWith(token)) { // containing proper Claims
                validTokens.add(token);
                return validTokens;
            }
            // if locality of Tokens is not required, Home Tokens from services belonging to federation should be processed
            if (!requireAllLocalTokens
                    && token.getType().equals(Token.Type.HOME)
                    && !token.getClaims().getIssuer().equals(localPlatformIdentifier) // a HOME token which is not ours
                    && federationMembers.contains(token.getClaims().getIssuer())) {
                // check can be missed when federation members are known to local Policy Enforcer
                //if (checkFederationClaims(token)) {
                validTokens.add(token);
                return validTokens;
                //}
            }
            // a foreign token issued by member with the proper key should be processed for searching the federation id
            if (token.getType().equals(Token.Type.FOREIGN) // an exchanged token
                    && token.getClaims().getIssuer().equals(localPlatformIdentifier) // issued by the local service
                    && federationMembers.contains(token.getClaims().getSubject().split(CryptoHelper.FIELDS_DELIMITER)[1])) { // the federation still harbour the platform the client comes from
                // check can be missed when federation members are known to local Policy Enforcer
                //if (checkFederationClaims(token)) {
                validTokens.add(token);
                return validTokens;
                // }
            }
        }
        return validTokens;
    }

    private boolean checkFederationClaims(Token token) {
        for (String claimKey : token.getClaims().keySet()) {
            if (claimKey.startsWith(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + SecurityConstants.FEDERATION_CLAIM_KEY_PREFIX))
                // checking if federation claims have our needed id
                if (token.getClaims().get(claimKey).toString().equals(federationIdentifier)) {
                    return true;
                }
        }
        return false;
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
