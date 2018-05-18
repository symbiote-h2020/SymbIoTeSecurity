package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.BarteralAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
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
     * Allows registering coupon in the Core BTM."
     *@param couponString to register
     *@return status of the operation (true - success)
     */
    boolean registerCoupon(String couponString) throws BTMException;

    /**
     * Coupon validation in Core BTM
     *
     * @param couponString for validation
     * @return couponValidity containing information about remaining usages/time and validation status
     */
    CouponValidity isCouponValid(String couponString) throws BTMException;

    /**
     * Coupon consumption in the Core BTM
     *
     * @param couponString for consumption
     * @return consumption status (true - success)
     */
    boolean consumeCoupon(String couponString) throws BTMException;


    /**
     * Ask for authorization of the barteral access
     * @param barteralAccessRequest request containing information about client's platform, resource Id and type of access
     * @return information if access is granted
     */
    boolean authorizeBarteralAccess(BarteralAccessRequest barteralAccessRequest) throws BTMException;

    /**
     * asks BTM for coupon to access the resource
     *
     * @param couponRequest request containing information about platform, type of access
     * @return coupon string
     */
    String getCoupon(CouponRequest couponRequest) throws BTMException, ValidationException;


}
