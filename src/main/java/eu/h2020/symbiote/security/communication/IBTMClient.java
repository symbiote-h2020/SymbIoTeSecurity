package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;

/**
 * Crude RMI-like client's interface to the Bartening and Trading module.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikolaj Dobski (PSNC)
 */
public interface IBTMClient {

    /**
     * Allows the user to revoke coupons
     *
     * @param revocationRequest required to revoke coupon.
     * @return the revocation status
     */
    String revokeCoupon(RevocationRequest revocationRequest) throws
            InvalidArgumentsException,
            WrongCredentialsException,
            AAMException;

    /**
     * Allows the user to use the coupon
     *
     * @param coupon - coupon to be consumed
     * @return TODO
     */
    boolean consumeCoupon(String coupon) throws AAMException, MalformedJWTException, WrongCredentialsException, JWTCreationException;

    /**
     * TODO @JT change documentation
     *
     * @param loginRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildJWTAcquisitionRequest(HomeCredentials)}
     *                     and TODO
     * @return coupon
     */
    String getDiscreteCoupon(String loginRequest) throws
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException,
            AAMException;

    /**
     * @param coupon that is to be validated
     * @return validation status
     */
    CouponValidationStatus validateCoupon(String coupon) throws AAMException;
}
