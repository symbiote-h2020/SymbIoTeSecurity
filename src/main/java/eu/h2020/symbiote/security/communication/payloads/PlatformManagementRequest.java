package eu.h2020.symbiote.security.communication.payloads;

/**
 * Describes platform registration in AAM payload.
 *
 * TODO update to contain operation enum on the platform
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Maksymilian Marcinowski (PSNC)
 */
public class PlatformManagementRequest {
    private Credentials AAMOwnerCredentials = new Credentials();
    private Credentials platformOwnerCredentials = new Credentials();
    private String platformInterworkingInterfaceAddress = "";
    private String platformInstanceId = "";
    private String platformInstanceFriendlyName;


    public PlatformManagementRequest() {
        // required for serialization
    }

    /**
     * For use when a Platform Owner is fine with generated platform identifier
     *
     * @param AAMOwnerCredentials                  used to authorize this request
     * @param platformOwnerCredentials                 used to register the platform owner in the database
     * @param platformInterworkingInterfaceAddress used to point symbiote users to possible login entry points
     * @param platformInstanceFriendlyName         a label for the end user to be able to identify the login entry point
     */
    public PlatformManagementRequest(Credentials AAMOwnerCredentials,
                                     Credentials platformOwnerCredentials,
                                     String platformInterworkingInterfaceAddress,
                                     String platformInstanceFriendlyName) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
        this.platformOwnerCredentials = platformOwnerCredentials;
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
    }

    /**
     * For use when a Platform Owner wants a preferred platform identifier
     * * @param AAMOwnerCredentials used to authorize this request
     *
     * @param platformOwnerCredentials             used to register the platform owner in the database
     * @param platformInterworkingInterfaceAddress used to point symbiote users to possible login entry points
     * @param platformInstanceFriendlyName         a label for the end user to be able to identify the login entry point
     * @param preferredPlatformInstanceID          when a Platform Owner preferres his own platform identifier
     */
    public PlatformManagementRequest(Credentials AAMOwnerCredentials,
                                     Credentials platformOwnerCredentials,
                                     String platformInterworkingInterfaceAddress,
                                     String platformInstanceFriendlyName,
                                     String preferredPlatformInstanceID) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
        this.platformInstanceId = preferredPlatformInstanceID;
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
        this.platformOwnerCredentials = platformOwnerCredentials;
    }

    public Credentials getPlatformOwnerCredentials() {
        return platformOwnerCredentials;
    }

    public void setPlatformOwnerDetails(Credentials platformOwnerCredentials) {
        this.platformOwnerCredentials = platformOwnerCredentials;
    }

    public String getPlatformInstanceId() {
        return platformInstanceId;
    }

    public void setPlatformInstanceId(String platformInstanceId) {
        this.platformInstanceId = platformInstanceId;
    }

    public String getPlatformInterworkingInterfaceAddress() {
        return platformInterworkingInterfaceAddress;
    }

    public void setPlatformInterworkingInterfaceAddress(String platformInterworkingInterfaceAddress) {
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
    }

    public Credentials getAAMOwnerCredentials() {
        return AAMOwnerCredentials;
    }

    public void setAAMOwnerCredentials(Credentials AAMOwnerCredentials) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
    }

    public String getPlatformInstanceFriendlyName() {
        return platformInstanceFriendlyName;
    }

    public void setPlatformInstanceFriendlyName(String platformInstanceFriendlyName) {
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
    }
}