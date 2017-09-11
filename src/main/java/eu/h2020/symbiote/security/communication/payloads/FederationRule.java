package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.data.annotation.Id;

import java.util.HashSet;
import java.util.Set;

/**
 * Required by the AAMs to exchange received remote HOME tokens into FOREIGN tokens containing the federation attributes.
 */
public class FederationRule {
    @Id
    private String federationId = "";
    private Set<String> platformIds = new HashSet<>();

    @JsonCreator
    public FederationRule(@JsonProperty("federationId") String federationId, @JsonProperty("platformIds") Set<String> platformIds) {
        this.federationId = federationId;
        this.platformIds = platformIds;
    }

    public String getFederationId() {
        return federationId;
    }

    public Set<String> getPlatformIds() {
        return platformIds;
    }

    public void addPlatform(String platformId) {
        platformIds.add(platformId);
    }

    public void deletePlatform(String platformId) {
        platformIds.remove(platformId);
    }

    public boolean containPlatform(String platformId) {
        return platformIds.contains(platformId);
    }
}
