package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.FailedFederationAuthorizationReport;
import feign.Headers;
import feign.RequestLine;
import feign.Response;

/**
 * Access to services provided by ADMs
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IFeignADMClient {

    @RequestLine("POST " + SecurityConstants.LOG_FAIL_FEDERATION_AUTHORIZATION)
    @Headers("Content-Type: application/json")
    Response reportFailedFederatedAuthorization(FailedFederationAuthorizationReport report);

}