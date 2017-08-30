package eu.h2020.symbiote.security.communication.payloads;

import java.util.*;

/**
 * Utility class for containing a set of {@link SecurityCredentials} objects and current timestamp used in the
 * challenge-response procedure ({@link eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper}).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 */
public class SecurityRequest {

    private final Set<SecurityCredentials> securityCredentials;
    private final long timestamp;

    public SecurityRequest(Set<SecurityCredentials> securityCredentials, Long timestamp) {
        this.securityCredentials = securityCredentials;
        this.timestamp = timestamp;
    }


    /**
     * @param splitSecurityRequest contains map of TODO add fields to constants
     *                             X-Auth-Timestamp -> Timestamp
     *                             X-Auth-Size -> Size of the SecurityCredentials Set
     *                             X-Auth-1..n -> SecurityCredentials
     */
    public SecurityRequest(Map<String, List<String>> splitSecurityRequest) {
        // TODO
        this.securityCredentials = new HashSet<>();
        this.timestamp = new Date().getTime();
    }

    public Set<SecurityCredentials> getSecurityCredentials() {
        return securityCredentials;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public Map<String, String> splitIntoStrings() {
        // TODO
        return new HashMap<>();

    }
}
