package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.FederationGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.communication.payloads.OriginPlatformGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import feign.QueryMap;
import feign.RequestLine;

import java.util.Map;
import java.util.Optional;

/**
 * Access to internal symbiote services provided by Anomaly Detection Module
 * e.g. Trust Manager data source relevant to federations
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IFeignADMComponentClient {

    /**
     * Acquire platform misdeeds reports needed for trust calculation, grouped by search origin platforms
     *
     * @see IComponentSecurityHandler#getFederationGroupedPlatformMisdeedsReports(Optional, Optional)
     */
    @RequestLine("GET " + SecurityConstants.ADM_GET_FEDERATED_MISDEEDS + "/bySearchOriginPlatform")
    Map<String, OriginPlatformGroupedPlatformMisdeedsReport> getMisdeedsGroupedByPlatform(@QueryMap Map<String, String> queryMap);

    /**
     * Acquire platform misdeeds reports needed for trust calculation, grouped by federations
     *
     * @see IComponentSecurityHandler#getFederationGroupedPlatformMisdeedsReports(Optional, Optional)
     */
    @RequestLine("GET " + SecurityConstants.ADM_GET_FEDERATED_MISDEEDS + "/byFederation")
    Map<String, FederationGroupedPlatformMisdeedsReport> getMisdeedsGroupedByFederations(@QueryMap Map<String, String> queryMap);
}
