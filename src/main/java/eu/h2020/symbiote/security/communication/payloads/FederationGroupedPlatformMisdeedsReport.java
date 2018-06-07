package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Describes platform misdeeds stored by ADM, grouped by federations
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class FederationGroupedPlatformMisdeedsReport extends PlatformMisdeedsReport {
    private final Map<String, Map<String, Integer>> detailsByFederation;

    @JsonCreator
    public FederationGroupedPlatformMisdeedsReport(@JsonProperty("totalMisdeeds") int totalMisdeeds,
                                                   @JsonProperty("detailsByFederation") Map<String, Map<String, Integer>> detailsByFederation) {
        super(totalMisdeeds);
        this.detailsByFederation = detailsByFederation;
    }

    /**
     * @return federations Ids map with detail information about access denials number for each searchOriginPlatform
     */
    public Map<String, Map<String, Integer>> getDetailsByFederation() {
        return detailsByFederation;
    }
}
