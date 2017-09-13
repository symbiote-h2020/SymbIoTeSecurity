package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Describes management of the localAttributes in AAM repository.
 *
 * @author Jakub Toczek (PSNC)
 */
public class LocalAttributesManagementRequest {

    private final Map<String, String> attributes;

    private final Credentials adminCredentials;
    private final OperationType operationType;

    /**
     *Constructor for LocalAttributesManagementRequest
     * @param attributes new attributes Map to replace those in AAM repository
     * @param adminCredentials admin username and password
     * @param operationType describe if we want to acquire actual attributes from AAM repository or replace them
     */
    @JsonCreator
    public LocalAttributesManagementRequest(
            @JsonProperty("attributes") Map<String, String> attributes,
            @JsonProperty("adminCredentials") Credentials adminCredentials,
            @JsonProperty("operationType") OperationType operationType) {
        this.attributes = attributes;
        this.adminCredentials = adminCredentials;
        this.operationType = operationType;
    }

    public OperationType getOperationType() {
        return operationType;
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public Credentials getAdminCredentials() {
        return adminCredentials;
    }

    public enum OperationType {
        //type of operation in which as a return we acquire localAttributes from repository
        READ,
        //type of operation in which we send localAttributes witch will replace those in repository
        WRITE
    }
}
