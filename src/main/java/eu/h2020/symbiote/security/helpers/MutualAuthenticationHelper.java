package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.ClientAuthenticationProof;
import eu.h2020.symbiote.security.communication.interfaces.payloads.ServiceAuthenticationProof;

import java.security.PrivateKey;
import java.util.Set;

/**
 * Provides helper methods to handle client-service authentication procedure.
 * <p>
 * TODO @Daniele
 */
public class MutualAuthenticationHelper {

    /**
     * Used by the client to generate a {@link ClientAuthenticationProof} to be attached to the business query so
     * that the service can confirm that the client should posses provided tokens
     *
     * @param authorizationCredentials matching the set of tokens used in the business query
     * @return the required payload
     */
    public static ClientAuthenticationProof getClientAuthenticationProof(Set<AuthorizationCredentials>
                                                                                 authorizationCredentials) {
        return null;
    }

    /**
     * Used by the service to handle the {@link ClientAuthenticationProof}
     *
     * @param authorizationTokens       attached to the business query
     * @param clientAuthenticationProof attached to the business query
     * @return true if the client should be in possession of the given tokens
     */
    public static boolean isClientAuthentic(Set<Token> authorizationTokens, ClientAuthenticationProof
            clientAuthenticationProof) {
        return true;
    }

    /**
     * Used by the service to generate the {@link ServiceAuthenticationProof} required by the client to confirm the
     * service authenticity
     *
     * @param servicePrivateKey used the sign the payload
     * @param clientToken       used to encrypt the payload
     * @return the required payload
     */
    public static ServiceAuthenticationProof getServiceAuthenticationProof(PrivateKey servicePrivateKey, Token
            clientToken) {
        return null;
    }

    /**
     * Used by the client to handle the {@link ServiceAuthenticationProof}
     *
     * @param serviceAuthenticationProof that should prove the service's authenticity
     * @param serviceCertificate         used verify the payload signature
     * @param clientKey                  used to decrypt the payload
     * @return true if the service is genuine
     */
    public static boolean isServiceAuthentic(ServiceAuthenticationProof serviceAuthenticationProof, Certificate
            serviceCertificate, PrivateKey clientKey) {
        return true;
    }

}
