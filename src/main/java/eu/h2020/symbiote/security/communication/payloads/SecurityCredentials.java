package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
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
                               Optional<String> clientCertificateSigningAAMCertificate,
                               Optional<String> foreignTokenIssuingAAMCertificate) {
        this.token = token;
        this.authenticationChallenge = authenticationChallenge.orElse("");
        this.clientCertificate = clientCertificate.orElse("");
        this.clientCertificateSigningAAMCertificate = clientCertificateSigningAAMCertificate.orElse("");
        this.foreignTokenIssuingAAMCertificate = foreignTokenIssuingAAMCertificate.orElse("");
    }

    /**
     * @param token                                  only @{@link Type#HOME} or @{@link Type#FOREIGN}
     * @param authenticationChallenge                generated using @MutualAuthenticationHelper{@link #getAuthenticationChallenge()}
     * @param clientCertificate                      (optional for offline validation) matching token SPK claim
     * @param clientCertificateSigningAAMCertificate (optional for offline validation) matching clientCertificate signature
     * @param foreignTokenIssuingAAMCertificate      (optional for offline validation) matching @{@link Type#FOREIGN} ISS and IPK claims
     */
    @JsonCreator
    public SecurityCredentials(@JsonProperty("token") String token,
                               @JsonProperty("authenticationChallenge") String authenticationChallenge,
                               @JsonProperty("clientCertificate") String clientCertificate,
                               @JsonProperty("clientCertificateSigningAAMCertificate") String clientCertificateSigningAAMCertificate,
                               @JsonProperty("foreignTokenIssuingAAMCertificate") String foreignTokenIssuingAAMCertificate) {
        this(token, Optional.of(authenticationChallenge), Optional.of(clientCertificate),
                Optional.of(clientCertificateSigningAAMCertificate),
                Optional.of(foreignTokenIssuingAAMCertificate));

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SecurityCredentials that = (SecurityCredentials) o;

        if (!token.equals(that.token)) return false;
        if (!authenticationChallenge.equals(that.authenticationChallenge)) return false;
        if (!clientCertificate.equals(that.clientCertificate)) return false;
        if (!clientCertificateSigningAAMCertificate.equals(that.clientCertificateSigningAAMCertificate)) return false;
        return foreignTokenIssuingAAMCertificate.equals(that.foreignTokenIssuingAAMCertificate);
    }

    @Override
    public int hashCode() {
        int result = token.hashCode();
        result = 31 * result + authenticationChallenge.hashCode();
        result = 31 * result + clientCertificate.hashCode();
        result = 31 * result + clientCertificateSigningAAMCertificate.hashCode();
        result = 31 * result + foreignTokenIssuingAAMCertificate.hashCode();
        return result;
    }
}
