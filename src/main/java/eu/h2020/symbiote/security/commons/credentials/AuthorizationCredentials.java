package eu.h2020.symbiote.security.commons.credentials;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.communication.payloads.AAM;

/**
 * Set of credentials required to attempt SymbIoTe authorization.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class AuthorizationCredentials {
    /**
     * passed as part of the business query that is authorization-protected
     */
    public final Token authorizationToken;

    /**
     * AAM that issued the authorizationToken
     */
    public final AAM tokenIssuingAAM;
    /**
     * used on client side only to support:
     * - generation of signed objects for tokens ownership proof (client authentication)
     */
    public final HomeCredentials homeCredentials;

    /**
     * @param authorizationToken used for authorization
     * @param tokenIssuingAAM    that issued the aforementioned token
     * @param homeCredentials    that were used to acquire the aforementioned token (HOME) or the token used to get the attached FOREIGN token
     */
    public AuthorizationCredentials(Token authorizationToken, AAM tokenIssuingAAM, HomeCredentials homeCredentials) {
        this.authorizationToken = authorizationToken;
        this.tokenIssuingAAM = tokenIssuingAAM;
        this.homeCredentials = homeCredentials;
    }
}
