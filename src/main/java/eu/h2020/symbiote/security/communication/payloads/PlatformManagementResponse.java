package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;

/**
 * Describes a response for platform registration sent by AAM
 *
 * @author Maksymilian Marcinowski (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class PlatformManagementResponse {
    private final String platformId;
    private final ManagementStatus registrationStatus;

    @JsonCreator
    public PlatformManagementResponse(@JsonProperty("registeredPlatformId") String registeredPlatformId,
                                      @JsonProperty("registrationStatus") ManagementStatus registrationStatus) {
        this.platformId = registeredPlatformId;
        this.registrationStatus = registrationStatus;
    }

    /**
     * @return platform identifier for given platform owner, to be used later in Registry
     */
    public String getPlatformId() {
        return platformId;
    }

    public ManagementStatus getRegistrationStatus() {
        return registrationStatus;
    }
}
