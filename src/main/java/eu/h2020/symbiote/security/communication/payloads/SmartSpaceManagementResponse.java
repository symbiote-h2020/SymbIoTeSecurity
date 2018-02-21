package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;

/**
 * Describes a response for Smart Space registration sent by AAM
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class SmartSpaceManagementResponse {
    private final String smartSpaceId;
    private final ManagementStatus managementStatus;

    @JsonCreator
    public SmartSpaceManagementResponse(@JsonProperty("smartSpaceId") String smartSpaceId,
                                        @JsonProperty("managementStatus") ManagementStatus managementStatus) {
        this.smartSpaceId = smartSpaceId;
        this.managementStatus = managementStatus;
    }

    /**
     * @return smart space identifier for given smart space owner, to be used later in Registry
     */
    public String getSmartSpaceId() {
        return smartSpaceId;
    }

    public ManagementStatus getManagementStatus() {
        return managementStatus;
    }
}
