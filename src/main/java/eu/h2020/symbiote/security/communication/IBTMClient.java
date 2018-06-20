package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.BarteredAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;

/**
 * Crude RMI-like client's interface to the Bartering and Trading module.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikolaj Dobski (PSNC)
 */
public interface IBTMClient {

    /**
     * //TODO consumption of the coupon is nor transactional or reversible, it can consume coupon no matter the result of this method,
     * Ask for authorization of the barteral access
     * @param barteredAccessRequest request containing information about client's platform, resource Id and type of access
     * @return information if access is granted
     */
    //TODO change the return to HttpStatus or validity.
    boolean authorizeBarteredAccess(BarteredAccessRequest barteredAccessRequest) throws BTMException;

    /**
     * //TODO move this class to other class
     * asks BTM for coupon to access the resource
     *
     * @param couponRequest request containing information about platform, type of access
     * @return coupon string
     */
    String getCoupon(CouponRequest couponRequest) throws BTMException, ValidationException;


}
