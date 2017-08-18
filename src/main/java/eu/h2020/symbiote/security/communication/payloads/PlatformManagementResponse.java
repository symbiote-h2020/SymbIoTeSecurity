package eu.h2020.symbiote.security.communication.payloads;

import eu.h2020.symbiote.security.commons.enums.ManagementStatus;

/**
 * Describes a response for platform registration sent by AAM
 *
 * @author Maksymilian Marcinowski (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class PlatformManagementResponse {
    private String platformId = "";
    private ManagementStatus registrationStatus;

    public PlatformManagementResponse() {
        // used by serializer
    }

    public PlatformManagementResponse(String registeredPlatformId, ManagementStatus registrationStatus) {
        this.platformId = registeredPlatformId;
        this.registrationStatus = registrationStatus;
    }

    /**
     * @return platform identifier for given platform owner, to be used later in Registry
     */
    public String getPlatformId() {
        return platformId;
    }

    public void setPlatformId(String platformId) {
        this.platformId = platformId;
    }

    public ManagementStatus getRegistrationStatus() {
        return registrationStatus;
    }

    public void setRegistrationStatus(ManagementStatus registrationStatus) {
        this.registrationStatus = registrationStatus;
    }
}
