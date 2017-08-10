package eu.h2020.symbiote.security.communication.payloads;

/**
 * SymbIoTe-enabled IoT platform instance details registered in the Core AAM.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class OwnedPlatformDetails {

    private String platformInstanceId = "";
    private String platformInterworkingInterfaceAddress = "";
    private String platformInstanceFriendlyName = "";

    public OwnedPlatformDetails() {
        // for Jackson JSON
    }

    /**
     * @param platformInstanceId                   SymbIoTe-unique platform identifier
     * @param platformInterworkingInterfaceAddress Address where the Platform exposes its Interworking Interface
     * @param platformInstanceFriendlyName         a label for the end user to be able to identify the login endrypoint
     */
    public OwnedPlatformDetails(String platformInstanceId,
                                String platformInterworkingInterfaceAddress,
                                String platformInstanceFriendlyName) {
        this.platformInstanceId = platformInstanceId;
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
    }

    /**
     * @return SymbIoTe-unique platform identifier
     */
    public String getPlatformInstanceId() {
        return platformInstanceId;
    }

    public void setPlatformInstanceId(String platformInstanceId) {
        this.platformInstanceId = platformInstanceId;
    }

    /**
     * @return Address where the Platform exposes its Interworking Interface
     */
    public String getPlatformInterworkingInterfaceAddress() {
        return platformInterworkingInterfaceAddress;
    }

    public void setPlatformInterworkingInterfaceAddress(String platformInterworkingInterfaceAddress) {
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
    }

    /**
     * @return a label for the end user to be able to identify the login endrypoint
     */
    public String getPlatformInstanceFriendlyName() {
        return platformInstanceFriendlyName;
    }

    public void setPlatformInstanceFriendlyName(String platformInstanceFriendlyName) {
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
    }
}
