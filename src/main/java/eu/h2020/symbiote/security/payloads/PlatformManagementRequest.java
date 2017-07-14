package eu.h2020.symbiote.security.payloads;

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
    private UserDetails platformOwnerDetails = new UserDetails();
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
     * @param platformOwnerDetails                 used to register the platform owner in the database
     * @param platformInterworkingInterfaceAddress used to point symbiote users to possible login entry points
     * @param platformInstanceFriendlyName         a label for the end user to be able to identify the login entry point
     */
    public PlatformManagementRequest(Credentials AAMOwnerCredentials,
                                     UserDetails platformOwnerDetails,
                                     String platformInterworkingInterfaceAddress,
                                     String platformInstanceFriendlyName) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
        this.platformOwnerDetails = platformOwnerDetails;
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
    }

    /**
     * For use when a Platform Owner wants a preferred platform identifier
     * * @param AAMOwnerCredentials used to authorize this request
     *
     * @param platformOwnerDetails                 used to register the platform owner in the database
     * @param platformInterworkingInterfaceAddress used to point symbiote users to possible login entry points
     * @param platformInstanceFriendlyName         a label for the end user to be able to identify the login entry point
     * @param preferredPlatformInstanceID          when a Platform Owner preferres his own platform identifier
     */
    public PlatformManagementRequest(Credentials AAMOwnerCredentials,
                                     UserDetails platformOwnerDetails,
                                     String platformInterworkingInterfaceAddress,
                                     String platformInstanceFriendlyName,
                                     String preferredPlatformInstanceID) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
        this.platformInstanceId = preferredPlatformInstanceID;
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
        this.platformOwnerDetails = platformOwnerDetails;
    }

    public UserDetails getPlatformOwnerDetails() {
        return platformOwnerDetails;
    }

    public void setPlatformOwnerDetails(UserDetails platformOwnerDetails) {
        this.platformOwnerDetails = platformOwnerDetails;
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