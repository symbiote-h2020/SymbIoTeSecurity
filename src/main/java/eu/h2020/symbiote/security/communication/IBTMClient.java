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
     * Allows the user to revoke their coupons
     *
     * @param revocationRequest required to revoke a coupon.
     * @return revocation status
     */
    String revokeCoupon(RevocationRequest revocationRequest) throws
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException;

    /**
     * Allows the user to use the coupon to get access to another federated platform’s data under a bartering scenario
     * @param coupon - valid coupon to consume
     * @return true if consumed properly
     */
    boolean consumeCoupon(String coupon) throws MalformedJWTException, WrongCredentialsException, JWTCreationException, BTMException;

    /**
     * TODO @JT change documentation
     *
     * @param couponRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildJWTAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return coupon to access another federated platform’s data under a bartering scenario
     */
    String getDiscreteCoupon(String couponRequest) throws
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException,
            BTMException;

    /**
     * Allows the user to validate coupon
     * @param coupon for validation
     * @return validation status
     */
    CouponValidationStatus validateCoupon(String coupon) throws BTMException;
}
