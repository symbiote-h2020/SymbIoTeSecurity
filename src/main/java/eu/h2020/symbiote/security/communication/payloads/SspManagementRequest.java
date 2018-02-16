package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.enums.OperationType;

/**
 * Describes ssp registration in AAM payload.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class SspManagementRequest {


    private final Credentials aamOwnerCredentials;
    private final Credentials sspOwnerCredentials;
    private final String sspInstanceFriendlyName;
    private final OperationType operationType;
    private final boolean exposedInternalInterworkingInterfaceAddress;
    private String sspExternalInterworkingInterfaceAddress;
    private String sspInternalInterworkingInterfaceAddress;
    private String sspInstanceId;


    /**
     * For use when a Ssp Owner wants a preferred ssp identifier
     *
     * @param aamOwnerCredentials                         used to authorize this request
     * @param sspOwnerCredentials                         used to register the ssp owner in the database
     * @param sspExternalInterworkingInterfaceAddress     used to point symbiote users to possible login entry points
     * @param sspInternalInterworkingInterfaceAddress     used to point symbiote users to possible login entry points inside internal ssp network
     * @param sspInstanceFriendlyName                     a label for the end user to be able to identify the login entry point
     * @param operationType                               operation, that ssp owner wants to perform (CREATE, UPDATE, DELETE)
     * @param sspInstanceId                               when a SSP Owner preferres his own ssp identifier
     * @param exposedInternalInterworkingInterfaceAddress should InternalInterworkingInterface be exposed
     */
    @JsonCreator
    public SspManagementRequest(@JsonProperty("aamOwnerCredentials") Credentials aamOwnerCredentials,
                                @JsonProperty("sspOwnerCredentials") Credentials sspOwnerCredentials,
                                @JsonProperty("sspExternalInterworkingInterfaceAddress") String sspExternalInterworkingInterfaceAddress,
                                @JsonProperty("sspInternalInterworkingInterfaceAddress") String sspInternalInterworkingInterfaceAddress,
                                @JsonProperty("sspInstanceFriendlyName") String sspInstanceFriendlyName,
                                @JsonProperty("operationType") OperationType operationType,
                                @JsonProperty("sspInstanceId") String sspInstanceId,
                                @JsonProperty("exposedInternalInterworkingInterfaceAddress") boolean exposedInternalInterworkingInterfaceAddress) {
        this.aamOwnerCredentials = aamOwnerCredentials;
        this.sspOwnerCredentials = sspOwnerCredentials;
        this.sspExternalInterworkingInterfaceAddress = sspExternalInterworkingInterfaceAddress;
        this.sspInternalInterworkingInterfaceAddress = sspInternalInterworkingInterfaceAddress;
        this.sspInstanceFriendlyName = sspInstanceFriendlyName;
        this.operationType = operationType;
        this.sspInstanceId = sspInstanceId;
        this.exposedInternalInterworkingInterfaceAddress = exposedInternalInterworkingInterfaceAddress;
    }

    public Credentials getAamOwnerCredentials() {
        return aamOwnerCredentials;
    }

    public Credentials getSspOwnerCredentials() {
        return sspOwnerCredentials;
    }

    public String getSspExternalInterworkingInterfaceAddress() {
        return sspExternalInterworkingInterfaceAddress;
    }

    public void setSspExternalInterworkingInterfaceAddress(String sspExternalInterworkingInterfaceAddress) {
        this.sspExternalInterworkingInterfaceAddress = sspExternalInterworkingInterfaceAddress;
    }

    public String getSspInternalInterworkingInterfaceAddress() {
        return sspInternalInterworkingInterfaceAddress;
    }

    public void setSspInternalInterworkingInterfaceAddress(String sspInternalInterworkingInterfaceAddress) {
        this.sspInternalInterworkingInterfaceAddress = sspInternalInterworkingInterfaceAddress;
    }

    public String getSspInstanceFriendlyName() {
        return sspInstanceFriendlyName;
    }

    public OperationType getOperationType() {
        return operationType;
    }

    public String getSspInstanceId() {
        return sspInstanceId;
    }

    public void setSspInstanceId(String sspInstanceId) {
        this.sspInstanceId = sspInstanceId;
    }

    public boolean isExposedInternalInterworkingInterfaceAddress() {
        return exposedInternalInterworkingInterfaceAddress;
    }

}