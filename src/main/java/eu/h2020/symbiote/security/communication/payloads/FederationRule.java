package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.data.annotation.Id;

import java.util.HashMap;
import java.util.Map;

/**
 * Required by the AAMs to exchange received remote HOME tokens into FOREIGN tokens containing the federation attributes.
 */
public class FederationRule {
    @Id
    private String federationId = "";
    private Map<String, String> requiredAttributes = new HashMap<>();
    private Map<String, String> releasedFederatedAttributes = new HashMap<>();

    @JsonCreator
    public FederationRule(@JsonProperty("federationId") String federationId, @JsonProperty("requiredAttributes") Map<String, String> requiredAttributes, @JsonProperty("releasedFederatedAttributes") Map<String, String> releasedFederatedAttributes) {
        this.federationId = federationId;
        this.requiredAttributes = requiredAttributes;
        this.releasedFederatedAttributes = releasedFederatedAttributes;
    }

    public String getFederationId() {
        return federationId;
    }

    public Map<String, String> getRequiredAttributes() {
        return requiredAttributes;
    }

    public Map<String, String> getReleasedFederatedAttributes() {
        return releasedFederatedAttributes;
    }

}
