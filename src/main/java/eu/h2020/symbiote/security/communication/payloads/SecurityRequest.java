package eu.h2020.symbiote.security.communication.payloads;

import java.util.Set;

/**
 * Utility class for containing a set of {@link SecurityCredentials} objects and current timestamp used in the
 * challenge-response procedure ({@link eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper}).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 */
public class SecurityRequest {

    private Set<SecurityCredentials> securityCredentials;
    private final Long timestamp;

    public SecurityRequest(Set<SecurityCredentials> securityCredentials, Long timestamp) {
        this.securityCredentials = securityCredentials;
        this.timestamp = timestamp;
    }

    public Set<SecurityCredentials> getSecurityCredentials() {
        return securityCredentials;
    }

    public void setSecurityCredentials(Set<SecurityCredentials> securityCredentials) {
        this.securityCredentials = securityCredentials;
    }

    public Long getTimestamp() {
        return timestamp;
    }
}
