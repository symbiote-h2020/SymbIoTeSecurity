package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.BarteredAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import feign.Headers;
import feign.RequestLine;
import feign.Response;

/**
 * Access to services provided by Bartering and Trading module.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IFeignBTMComponentClient {

    @RequestLine("POST " + SecurityConstants.BTM_AUTHORIZE_BARTERAL_ACCESS)
    @Headers("Content-Type: application/json")
    Response authorizeBarteredAccess(BarteredAccessRequest barteredAccessRequest);

    @RequestLine("POST " + SecurityConstants.BTM_REVOKE_COUPON)
    @Headers("Content-Type: application/json")
    Response revokeCoupon(RevocationRequest revocationRequest);
}