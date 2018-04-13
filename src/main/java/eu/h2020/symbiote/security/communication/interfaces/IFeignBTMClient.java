package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;

/**
 * Access to services provided by Bartening and Traiding module.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IFeignBTMClient {

    @RequestLine("POST " + SecurityConstants.BTM_GET_DISCRETE_COUPON)
    @Headers({"Content-Type: text/plain", "Accept: text/plain",
            SecurityConstants.COUPON_HEADER_NAME + ": " + "{coupon}"})
    Response getDiscreteCoupon(@Param("coupon") String loginRequest);

    @RequestLine("POST " + SecurityConstants.BTM_CONSUME_COUPON)
    @Headers({"Content-Type: text/plain", "Accept: text/plain",
            SecurityConstants.COUPON_HEADER_NAME + ": " + "{coupon}"})
    Response consumeCoupon(@Param("coupon") String coupon);

    @RequestLine("POST " + SecurityConstants.BTM_REVOKE_COUPON)
    @Headers("Content-Type: application/json")
    Response revokeCoupon(RevocationRequest revocationRequest);

    @RequestLine("POST " + SecurityConstants.BTM_VALIDATE_COUPON)
    @Headers({SecurityConstants.COUPON_HEADER_NAME + ": {coupon}",
            "Accept: application/json"})
    CouponValidationStatus validateCoupon(@Param("coupon") String coupon);
}