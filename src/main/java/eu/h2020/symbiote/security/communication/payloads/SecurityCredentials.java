package eu.h2020.symbiote.security.communication.payloads;

/**
 * Utility class for containing a token (used for authorization and access polices), the authentication challenge used
 * in the challenge-response procedure ({@link eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper}) for
 * authentication (mandatory for HOME and FOREIGN tokens) and the optional client and signing AAM platform certificate
 * strings (in PEM format).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 *
 */
public class SecurityCredentials {

    private String token;
    private String authenticationChallenge = "";
    private String clientCertificate = "";
    private String signingAAMCertificate = "";

    public SecurityCredentials(String token, String authenticationChallenge, String clientCertificate, String signingAAMCertificate) {
        this.token = token;
        this.authenticationChallenge = authenticationChallenge;
        this.clientCertificate = clientCertificate;
        this.signingAAMCertificate = signingAAMCertificate;
    }

    public SecurityCredentials(String token, String authenticationChallenge) {
        this.token = token;
        this.authenticationChallenge = authenticationChallenge;
    }

    public SecurityCredentials(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getAuthenticationChallenge() {
        return authenticationChallenge;
    }

    public void setAuthenticationChallenge(String authenticationChallenge) {
        this.authenticationChallenge = authenticationChallenge;
    }

    public String getClientCertificate() {
        return clientCertificate;
    }

    public void setClientCertificate(String clientCertificate) {
        this.clientCertificate = clientCertificate;
    }

    public String getSigningAAMCertificate() {
        return signingAAMCertificate;
    }

    public void setSigningAAMCertificate(String signingAAMCertificate) {
        this.signingAAMCertificate = signingAAMCertificate;
    }
}
