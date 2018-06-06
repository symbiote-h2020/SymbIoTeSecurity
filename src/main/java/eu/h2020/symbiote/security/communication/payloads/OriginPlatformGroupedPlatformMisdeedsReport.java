package eu.h2020.symbiote.security.communication.payloads;

import java.util.Map;

/**
 * Describes platform misdeeds stored by ADM, grouped by originPlatforms
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class OriginPlatformGroupedPlatformMisdeedsReport extends PlatformMisdeedsReport {
    private final Map<String, Map<String, Integer>> detailsBySearchOriginPlatform;

    public OriginPlatformGroupedPlatformMisdeedsReport(int totalMisdeeds,
                                                       Map<String, Map<String, Integer>> detailsBySearchOriginPlatform) {
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
