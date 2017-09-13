package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashSet;
import java.util.Set;

/**
 * Describes management of the federation rules.
 *
 * @author Jakub Toczek (PSNC)
 */
public class FederationRuleManagementRequest {
    private final Credentials adminCredentials;
    private final String federationRuleId;
    private final Set<String> platformIds;
    private final OperationType operationType;

    /**
     * Constructor used to build FederationRuleManagementRequest operations
     *
     * @param adminCredentials credentials of the admin.
     * @param federationRuleId id of the federation rule.
     * @param platformIds      ids of the platforms taking part in federation.
     * @param operationType    type of the operation.
     */
    @JsonCreator
    public FederationRuleManagementRequest(@JsonProperty("adminCredentials") Credentials adminCredentials,
                                           @JsonProperty("federationRuleId") String federationRuleId,
                                           @JsonProperty("platformIds") Set<String> platformIds,
                                           @JsonProperty("operationType") OperationType operationType) {
        this.adminCredentials = adminCredentials;
        this.federationRuleId = federationRuleId;
        this.platformIds = platformIds;
        this.operationType = operationType;
    }

    /**
     * Constructor used to build FederationRuleManagementRequest for DELETE and READ operations
     *
     * @param adminCredentials credentials of the admin.
     * @param federationRuleId id of the federation rule to READ or DELETE.
     * @param operationType    type of the operation.
     */
    public FederationRuleManagementRequest(@JsonProperty("adminCredentials") Credentials adminCredentials,
                                           @JsonProperty("federationRuleId") String federationRuleId,
                                           @JsonProperty("operationType") OperationType operationType) {
        this(adminCredentials, federationRuleId, new HashSet<>(), operationType);
    }

    public Set<String> getPlatformIds() {
        return platformIds;
    }

    public Credentials getAdminCredentials() {
        return adminCredentials;
    }

    public String getFederationRuleId() {
        return federationRuleId;
    }

    public OperationType getOperationType() {
        return operationType;
    }

    public enum OperationType {
        //type of operation in which we create federation rule under provided federationRuleId
        CREATE,
        //type of operation in which as a return we acquire federation rule under provided federationRuleId
        READ,
        //type of operation in which we replace requiredAttributes and releasedFederatedAttributes under provided federationRuleId
        UPDATE,
        //type of operation in which we delete federation rule under provided federationRuleId
        DELETE
    }
}
