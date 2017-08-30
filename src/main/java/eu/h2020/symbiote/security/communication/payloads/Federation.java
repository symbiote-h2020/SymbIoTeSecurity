package eu.h2020.symbiote.security.communication.payloads;

import org.springframework.data.annotation.Id;

import java.util.HashMap;
import java.util.Map;

public class Federation {
    @Id
    private String federationId = "";
    private Map<String, String> requiredAttributes = new HashMap<>();
    private Map<String, String> releasedFederatedAttributes = new HashMap<>();

    public Federation(String federationId, Map<String, String> requiredAttributes, Map<String, String> releasedFederatedAttributes) {
        this.federationId = federationId;
        this.requiredAttributes = requiredAttributes;
        this.releasedFederatedAttributes = releasedFederatedAttributes;
    }

    public String getFederationId() {
        return federationId;
    }

    public void setFederationId(String federationId) {
        this.federationId = federationId;
    }

    public Map<String, String> getRequiredAttributes() {
        return requiredAttributes;
    }

    public void setRequiredAttributes(Map<String, String> requiredAttributes) {
        this.requiredAttributes = requiredAttributes;
    }

    public Map<String, String> getReleasedFederatedAttributes() {
        return releasedFederatedAttributes;
    }

    public void setReleasedFederatedAttributes(Map<String, String> releasedFederatedAttributes) {
        this.releasedFederatedAttributes = releasedFederatedAttributes;
    }
}
