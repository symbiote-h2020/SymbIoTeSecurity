package eu.h2020.symbiote.security.commons.credentials;

import eu.h2020.symbiote.security.commons.Token;

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
     * used on client side only to support:
     * - {@link eu.h2020.symbiote.security.communication.interfaces.payloads.ClientAuthenticationProof} generation
     * - {@link eu.h2020.symbiote.security.communication.interfaces.payloads.ServiceAuthenticationProof} decryption
     */
    public final HomeCredentials homeCredentials;

    public AuthorizationCredentials(Token authorizationToken, HomeCredentials homeCredentials) {
        this.authorizationToken = authorizationToken;
        this.homeCredentials = homeCredentials;
    }
}
