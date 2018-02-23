package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.enums.OperationType;

/**
 * Describes smart space registration in AAM payload.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class SmartSpaceManagementRequest {


    private final Credentials aamOwnerCredentials;
    private final Credentials serviceOwnerCredentials;
    private final String instanceFriendlyName;
    private final OperationType operationType;
    private final boolean exposingSiteLocalAddress;
    private String gatewayAddress;
    private String siteLocalAddress;
    private String instanceId;


    /**
     * For use when a Smart Space Owner wants a preferred smart space identifier
     *
     * @param aamOwnerCredentials        used to authorize this request
     * @param serviceOwnerCredentials    used to register the smartSpaceOwner in the database
     * @param gatewayAddress             used to point symbiote users to possible entry points available from Internet
     * @param siteLocalAddress           used to point symbiote users to possible entry points available from internal smart space network
     * @param instanceFriendlyName       a label for the end user to be able to identify the login entry point
     * @param operationType              operation, that smart space owner wants to perform (CREATE, UPDATE, DELETE)
     * @param instanceId                 when a Smart Space Owner prefers his own Smart Space identifier
     * @param exposingSiteLocalAddress   should siteLocalAddress be exposed
     */
    @JsonCreator
    public SmartSpaceManagementRequest(@JsonProperty("aamOwnerCredentials") Credentials aamOwnerCredentials,
                                       @JsonProperty("serviceOwnerCredentials") Credentials serviceOwnerCredentials,
                                       @JsonProperty("gatewayAddress") String gatewayAddress,
                                       @JsonProperty("siteLocalAddress") String siteLocalAddress,
                                       @JsonProperty("instanceFriendlyName") String instanceFriendlyName,
                                       @JsonProperty("operationType") OperationType operationType,
                                       @JsonProperty("instanceId") String instanceId,
                                       @JsonProperty("exposingSiteLocalAddress") boolean exposingSiteLocalAddress) {
        this.aamOwnerCredentials = aamOwnerCredentials;
        this.serviceOwnerCredentials = serviceOwnerCredentials;
        this.gatewayAddress = gatewayAddress;
        this.siteLocalAddress = siteLocalAddress;
        this.instanceFriendlyName = instanceFriendlyName;
        this.operationType = operationType;
        this.instanceId = instanceId;
        this.exposingSiteLocalAddress = exposingSiteLocalAddress;
    }

    public Credentials getAamOwnerCredentials() {
        return aamOwnerCredentials;
    }

    public Credentials getServiceOwnerCredentials() {
        return serviceOwnerCredentials;
    }

    public String getGatewayAddress() {
        return gatewayAddress;
    }

    public void setGatewayAddress(String gatewayAddress) {
        this.gatewayAddress = gatewayAddress;
    }

    public String getSiteLocalAddress() {
        return siteLocalAddress;
    }

    public void setSiteLocalAddress(String siteLocalAddress) {
        this.siteLocalAddress = siteLocalAddress;
    }

    public String getInstanceFriendlyName() {
        return instanceFriendlyName;
    }

    public OperationType getOperationType() {
        return operationType;
    }

    public String getInstanceId() {
        return instanceId;
    }

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    public boolean isExposingSiteLocalAddress() {
        return exposingSiteLocalAddress;
    }

}