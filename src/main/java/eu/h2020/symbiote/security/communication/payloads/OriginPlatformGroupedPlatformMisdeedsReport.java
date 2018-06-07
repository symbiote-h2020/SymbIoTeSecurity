package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Describes platform misdeeds stored by ADM, grouped by originPlatforms
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class OriginPlatformGroupedPlatformMisdeedsReport extends PlatformMisdeedsReport {
    private final Map<String, Map<String, Integer>> detailsBySearchOriginPlatform;

    @JsonCreator
    public OriginPlatformGroupedPlatformMisdeedsReport(@JsonProperty("totalMisdeeds") int totalMisdeeds,
                                                       @JsonProperty("detailsBySearchOriginPlatform") Map<String, Map<String, Integer>> detailsBySearchOriginPlatform) {
        super(totalMisdeeds);
        this.detailsBySearchOriginPlatform = detailsBySearchOriginPlatform;
    }


    /**
     * @return search origins platform Ids map with detail information about access denials number in each federation
     */
    public Map<String, Map<String, Integer>> getDetailsBySearchOriginPlatform() {
        return detailsBySearchOriginPlatform;
    }
}
