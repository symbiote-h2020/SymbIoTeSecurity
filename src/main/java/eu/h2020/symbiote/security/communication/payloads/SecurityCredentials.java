package eu.h2020.symbiote.security.communication.payloads;

import eu.h2020.symbiote.security.commons.Token.Type;

import java.util.Optional;

/**
 * Utility class for containing a token (used for authorization and access polices), the authentication challenge used
 * in the challenge-response procedure ({@link eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper}) for
 * authentication (mandatory for HOME and FOREIGN tokens) and the optional certificates for offline validation
 * strings (in PEM format).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 */
public class SecurityCredentials {

    private final String token;
    private final String authenticationChallenge;
    private final String clientCertificate;
    private final String clientCertificateSigningAAMCertificate;
    private final String foreignTokenIssuingAAMCertificate;

    /**
     * @param token                                  only @{@link Type#HOME} or @{@link Type#FOREIGN}
     * @param authenticationChallenge                generated using @MutualAuthenticationHelper{@link #getAuthenticationChallenge()}
     * @param clientCertificate                      (optional for offline validation) matching token SPK claim
     * @param clientCertificateSigningAAMCertificate (optional for offline validation) matching clientCertificate signature
     * @param foreignTokenIssuingAAMCertificate      (optional for offline validation) matching @{@link Type#FOREIGN} ISS and IPK claims
     */
    public SecurityCredentials(String token,
                               Optional<String> authenticationChallenge,
                               Optional<String> clientCertificate,
                               Optional<String> clientCertificateSigningAAMCertificate, Optional<String> foreignTokenIssuingAAMCertificate) {
        this.token = token;
        this.authenticationChallenge = authenticationChallenge.orElse("");
        this.clientCertificate = clientCertificate.orElse("");
        this.clientCertificateSigningAAMCertificate = clientCertificateSigningAAMCertificate.orElse("");
        this.foreignTokenIssuingAAMCertificate = foreignTokenIssuingAAMCertificate.orElse("");
    }

    /**
     * Used only for @{@link Type#GUEST}
     *
     * @param guestToken to generate the service required payload.
     */
    public SecurityCredentials(String guestToken) {
        this.token = guestToken;
        this.authenticationChallenge = "";
        this.clientCertificate = "";
        this.clientCertificateSigningAAMCertificate = "";
        this.foreignTokenIssuingAAMCertificate = "";
    }

    public String getToken() {
        return token;
    }

    public String getAuthenticationChallenge() {
        return authenticationChallenge;
    }

    public String getClientCertificate() {
        return clientCertificate;
    }

    public String getClientCertificateSigningAAMCertificate() {
        return clientCertificateSigningAAMCertificate;
    }

    public String getForeignTokenIssuingAAMCertificate() {
        return foreignTokenIssuingAAMCertificate;
    }
}
