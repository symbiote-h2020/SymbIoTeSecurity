package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.BarteredAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;

/**
 * Crude RMI-like client's interface to the Bartering and Trading module.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikolaj Dobski (PSNC)
 */
public interface IBTMComponentClient {

    /**
     * //TODO consumption of the coupon is nor transactional or reversible, it can consume coupon no matter the result of this method,
     * Ask for authorization of the barteral access
     * @param barteredAccessRequest request containing information about client's platform, resource Id and type of access
     * @return information if access is granted
     */
    //TODO change the return to HttpStatus or validity.
    boolean authorizeBarteredAccess(BarteredAccessRequest barteredAccessRequest) throws BTMException;

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

}
