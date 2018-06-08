package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.FederationGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.communication.payloads.OriginPlatformGroupedPlatformMisdeedsReport;
import feign.QueryMap;
import feign.RequestLine;

import java.util.Map;

public interface IFeignADMComponentClient {

    @RequestLine("GET " + SecurityConstants.ADM_GET_FEDERATED_MISDEEDS + "/bySearchOriginPlatform")
    Map<String, OriginPlatformGroupedPlatformMisdeedsReport> getMisdeedsGroupedByPlatform(@QueryMap Map<String, String> queryMap);

    @RequestLine("GET " + SecurityConstants.ADM_GET_FEDERATED_MISDEEDS + "/byFederation")
    Map<String, FederationGroupedPlatformMisdeedsReport> getMisdeedsGroupedByFederations(@QueryMap Map<String, String> queryMap);
}
