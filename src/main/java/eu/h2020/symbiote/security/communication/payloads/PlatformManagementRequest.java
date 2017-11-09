package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.enums.OperationType;

/**
 * Describes platform registration in AAM payload.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Maksymilian Marcinowski (PSNC)
 */
public class PlatformManagementRequest {
    private final Credentials aamOwnerCredentials;
    private final Credentials platformOwnerCredentials;
    private final String platformInterworkingInterfaceAddress;
    private final String platformInstanceFriendlyName;
    private final OperationType operationType;
    private String platformInstanceId;

    /**
     * For use when a Platform Owner is fine with generated platform identifier
     *
     * @param aamOwnerCredentials                  used to authorize this request
     * @param platformOwnerCredentials             used to register the platform owner in the database
     * @param platformInterworkingInterfaceAddress used to point symbiote users to possible login entry points
     * @param platformInstanceFriendlyName         a label for the end user to be able to identify the login entry point
     */
    public PlatformManagementRequest(Credentials aamOwnerCredentials,
                                     Credentials platformOwnerCredentials,
                                     String platformInterworkingInterfaceAddress,
                                     String platformInstanceFriendlyName,
                                     OperationType operationType) {
        this(aamOwnerCredentials,
                platformOwnerCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                "",
                operationType);
    }

    /**
     * For use when a Platform Owner wants a preferred platform identifier
     * * @param aamOwnerCredentials used to authorize this request
     *
     * @param aamOwnerCredentials                  used to authorize this request
     * @param platformOwnerCredentials             used to register the platform owner in the database
     * @param platformInterworkingInterfaceAddress used to point symbiote users to possible login entry points
     * @param platformInstanceFriendlyName         a label for the end user to be able to identify the login entry point
     * @param preferredPlatformInstanceID          when a Platform Owner preferres his own platform identifier
     */
    @JsonCreator
    public PlatformManagementRequest(@JsonProperty("aamOwnerCredentials") Credentials aamOwnerCredentials,
                                     @JsonProperty("platformOwnerCredentials") Credentials platformOwnerCredentials,
                                     @JsonProperty("platformInterworkingInterfaceAddress") String platformInterworkingInterfaceAddress,
                                     @JsonProperty("platformInstanceFriendlyName") String platformInstanceFriendlyName,
                                     @JsonProperty("preferredPlatformInstanceID") String preferredPlatformInstanceID,
                                     @JsonProperty("operationType") OperationType operationType) {
        this.aamOwnerCredentials = aamOwnerCredentials;
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
        this.platformInstanceId = preferredPlatformInstanceID;
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
        this.platformOwnerCredentials = platformOwnerCredentials;
        this.operationType = operationType;
    }

    public Credentials getPlatformOwnerCredentials() {
        return platformOwnerCredentials;
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

    public Credentials getAamOwnerCredentials() {
        return aamOwnerCredentials;
    }

    public String getPlatformInstanceFriendlyName() {
        return platformInstanceFriendlyName;
    }

    public OperationType getOperationType() {
        return operationType;
    }
}