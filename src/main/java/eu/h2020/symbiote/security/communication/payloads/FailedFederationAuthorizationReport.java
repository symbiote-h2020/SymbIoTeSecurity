package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Describes payload used to report failed authorization during getting access to the federated resource (where access should be provided)
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class FailedFederationAuthorizationReport {

    private final SecurityRequest securityRequest;
    private final String federationId;
    private final String resourcePlatformId;
    private final String searchOriginPlatformId;
    private final String resourceId;

    /**
     * Payload used to report failed authorization during getting access to the federated resource (where access should be provided)
     *
     * @param securityRequest        used during failed authorization
     * @param federationId           according to which resource access should be provided
     * @param resourcePlatformId     resource's platform
     * @param searchOriginPlatformId platform from which actor gained information about resource availability
     * @param resourceId             to which access was not granted
     */
    @JsonCreator
    public FailedFederationAuthorizationReport(@JsonProperty("securityRequest") SecurityRequest securityRequest,
                                               @JsonProperty("federationId") String federationId,
                                               @JsonProperty("resourcePlatformId") String resourcePlatformId,
                                               @JsonProperty("searchOriginPlatformId") String searchOriginPlatformId,
                                               @JsonProperty("resourceId") String resourceId) {
        this.securityRequest = securityRequest;
        this.federationId = federationId;
        this.resourcePlatformId = resourcePlatformId;
        this.searchOriginPlatformId = searchOriginPlatformId;
        this.resourceId = resourceId;
    }

    public String getSearchOriginPlatformId() {
        return searchOriginPlatformId;
    }

    public SecurityRequest getSecurityRequest() {
        return securityRequest;
    }

    public String getFederationId() {
        return federationId;
    }

    public String getResourceId() {
        return resourceId;
    }

    public String getResourcePlatformId() {
        return resourcePlatformId;
    }
}
