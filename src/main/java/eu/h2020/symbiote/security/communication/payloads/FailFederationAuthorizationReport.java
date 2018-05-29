package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class FailFederationAuthorizationReport {

    private SecurityRequest securityRequest;
    private String federationId;
    private String platformId;
    private String resourceId;

    @JsonCreator
    public FailFederationAuthorizationReport(@JsonProperty("securityRequest") SecurityRequest securityRequest,
                                             @JsonProperty("federationId") String federationId,
                                             @JsonProperty("platformId") String platformId,
                                             @JsonProperty("resourceId") String resourceId) {
        this.securityRequest = securityRequest;
        this.federationId = federationId;
        this.platformId = platformId;
        this.resourceId = resourceId;
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

    public String getPlatformId() {
        return platformId;
    }
}
