package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.FailedFederationAuthorizationReport;
import feign.Headers;
import feign.RequestLine;
import feign.Response;

/**
 * Access to client services provided by Anomaly Detection Module
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IFeignADMClient {

    @RequestLine("POST " + SecurityConstants.ADM_LOG_FAILED_FEDERATION_AUTHORIZATION)
    @Headers("Content-Type: application/json")
    Response reportFailedFederatedAuthorization(FailedFederationAuthorizationReport report);

}