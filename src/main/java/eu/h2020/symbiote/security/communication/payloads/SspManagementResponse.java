package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;

/**
 * Describes a response for ssp registration sent by AAM
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class SspManagementResponse {
    private final String sspId;
    private final ManagementStatus registrationStatus;

    @JsonCreator
    public SspManagementResponse(@JsonProperty("sspId") String sspId,
                                 @JsonProperty("registrationStatus") ManagementStatus registrationStatus) {
        this.sspId = sspId;
        this.registrationStatus = registrationStatus;
    }

    /**
     * @return ssp identifier for given ssp owner, to be used later in Registry
     */
    public String getSspId() {
        return sspId;
    }

    public ManagementStatus getRegistrationStatus() {
        return registrationStatus;
    }
}
