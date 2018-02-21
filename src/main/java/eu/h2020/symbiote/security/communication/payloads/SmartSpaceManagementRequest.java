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
    private final Credentials smartSpaceOwnerCredentials;
    private final String smartSpaceInstanceFriendlyName;
    private final OperationType operationType;
    private final boolean exposedInternalInterworkingInterfaceAddress;
    private String smartSpaceExternalInterworkingInterfaceAddress;
    private String smartSpaceInternalInterworkingInterfaceAddress;
    private String smartSpaceInstanceId;


    /**
     * For use when a Smart Space Owner wants a preferred smart space identifier
     *
     * @param aamOwnerCredentials                         used to authorize this request
     * @param smartSpaceOwnerCredentials                         used to register the smartSpaceOwner in the database
     * @param smartSpaceExternalInterworkingInterfaceAddress     used to point symbiote users to possible login entry points
     * @param smartSpaceInternalInterworkingInterfaceAddress     used to point symbiote users to possible login entry points inside internal smart space network
     * @param smartSpaceInstanceFriendlyName                     a label for the end user to be able to identify the login entry point
     * @param operationType                               operation, that smart space owner wants to perform (CREATE, UPDATE, DELETE)
     * @param smartSpaceInstanceId                               when a Smart Space Owner preferres his own Smart Space identifier
     * @param exposedInternalInterworkingInterfaceAddress should InternalInterworkingInterface be exposed
     */
    @JsonCreator
    public SmartSpaceManagementRequest(@JsonProperty("aamOwnerCredentials") Credentials aamOwnerCredentials,
                                       @JsonProperty("smartSpaceOwnerCredentials") Credentials smartSpaceOwnerCredentials,
                                       @JsonProperty("smartSpaceExternalInterworkingInterfaceAddress") String smartSpaceExternalInterworkingInterfaceAddress,
                                       @JsonProperty("smartSpaceInternalInterworkingInterfaceAddress") String smartSpaceInternalInterworkingInterfaceAddress,
                                       @JsonProperty("smartSpaceInstanceFriendlyName") String smartSpaceInstanceFriendlyName,
                                       @JsonProperty("operationType") OperationType operationType,
                                       @JsonProperty("smartSpaceInstanceId") String smartSpaceInstanceId,
                                       @JsonProperty("exposedInternalInterworkingInterfaceAddress") boolean exposedInternalInterworkingInterfaceAddress) {
        this.aamOwnerCredentials = aamOwnerCredentials;
        this.smartSpaceOwnerCredentials = smartSpaceOwnerCredentials;
        this.smartSpaceExternalInterworkingInterfaceAddress = smartSpaceExternalInterworkingInterfaceAddress;
        this.smartSpaceInternalInterworkingInterfaceAddress = smartSpaceInternalInterworkingInterfaceAddress;
        this.smartSpaceInstanceFriendlyName = smartSpaceInstanceFriendlyName;
        this.operationType = operationType;
        this.smartSpaceInstanceId = smartSpaceInstanceId;
        this.exposedInternalInterworkingInterfaceAddress = exposedInternalInterworkingInterfaceAddress;
    }

    public Credentials getAamOwnerCredentials() {
        return aamOwnerCredentials;
    }

    public Credentials getSmartSpaceOwnerCredentials() {
        return smartSpaceOwnerCredentials;
    }

    public String getSmartSpaceExternalInterworkingInterfaceAddress() {
        return smartSpaceExternalInterworkingInterfaceAddress;
    }

    public void setSmartSpaceExternalInterworkingInterfaceAddress(String smartSpaceExternalInterworkingInterfaceAddress) {
        this.smartSpaceExternalInterworkingInterfaceAddress = smartSpaceExternalInterworkingInterfaceAddress;
    }

    public String getSmartSpaceInternalInterworkingInterfaceAddress() {
        return smartSpaceInternalInterworkingInterfaceAddress;
    }

    public void setSmartSpaceInternalInterworkingInterfaceAddress(String smartSpaceInternalInterworkingInterfaceAddress) {
        this.smartSpaceInternalInterworkingInterfaceAddress = smartSpaceInternalInterworkingInterfaceAddress;
    }

    public String getSmartSpaceInstanceFriendlyName() {
        return smartSpaceInstanceFriendlyName;
    }

    public OperationType getOperationType() {
        return operationType;
    }

    public String getSmartSpaceInstanceId() {
        return smartSpaceInstanceId;
    }

    public void setSmartSpaceInstanceId(String smartSpaceInstanceId) {
        this.smartSpaceInstanceId = smartSpaceInstanceId;
    }

    public boolean isExposedInternalInterworkingInterfaceAddress() {
        return exposedInternalInterworkingInterfaceAddress;
    }

}