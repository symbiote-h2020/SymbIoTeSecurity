package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

/**
 * Describes smart space registration and management in AAM payload.
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
    private final String externalAddress;
    private final String siteLocalAddress;
    private final String instanceId;


    /**
     * For use when a Smart Space Owner wants a preferred smart space identifier
     *
     * @param aamOwnerCredentials        used to authorize this request
     * @param serviceOwnerCredentials    used to register the smartSpaceOwner in the database
     * @param externalAddress            used to point symbiote users to possible entry points available from the Internet
     * @param siteLocalAddress           used to point symbiote users to possible entry points available from within the smart space local network
     * @param instanceFriendlyName       a label for the end user to be able to identify the login entry point
     * @param operationType              operation, that smart space owner wants to perform (CREATE, UPDATE, DELETE)
     * @param instanceId                 when a Smart Space Owner prefers his own Smart Space identifier
     * @param exposingSiteLocalAddress   should the Core AAM advertise/expose the SSP's siteLocalAddress
     */
    @JsonCreator
    public SmartSpaceManagementRequest(@JsonProperty("aamOwnerCredentials") Credentials aamOwnerCredentials,
                                       @JsonProperty("serviceOwnerCredentials") Credentials serviceOwnerCredentials,
                                       @JsonProperty("externalAddress") String externalAddress,
                                       @JsonProperty("siteLocalAddress") String siteLocalAddress,
                                       @JsonProperty("instanceFriendlyName") String instanceFriendlyName,
                                       @JsonProperty("operationType") OperationType operationType,
                                       @JsonProperty("instanceId") String instanceId,
                                       @JsonProperty("exposingSiteLocalAddress") boolean exposingSiteLocalAddress) throws
            InvalidArgumentsException {
        this.aamOwnerCredentials = aamOwnerCredentials;
        this.serviceOwnerCredentials = serviceOwnerCredentials;

        if (!externalAddress.isEmpty() && !externalAddress.startsWith("https://"))
            throw new InvalidArgumentsException(InvalidArgumentsException.EXTERNAL_ADDRESS_MUST_START_WITH_HTTPS);
        this.externalAddress = externalAddress;

        this.instanceFriendlyName = instanceFriendlyName;
        this.operationType = operationType;
        this.instanceId = instanceId;

        if (exposingSiteLocalAddress
                && operationType != OperationType.DELETE
                && (siteLocalAddress == null || siteLocalAddress.isEmpty()))
                throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_SITE_LOCAL_ADDRESS);

        this.siteLocalAddress = siteLocalAddress;
        this.exposingSiteLocalAddress = exposingSiteLocalAddress;
    }

    public Credentials getAamOwnerCredentials() {
        return aamOwnerCredentials;
    }

    public Credentials getServiceOwnerCredentials() {
        return serviceOwnerCredentials;
    }

    public String getExternalAddress() {
        return externalAddress;
    }

    public String getSiteLocalAddress() {
        return siteLocalAddress;
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

    public boolean isExposingSiteLocalAddress() {
        return exposingSiteLocalAddress;
    }

}