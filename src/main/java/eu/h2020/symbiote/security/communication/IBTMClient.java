package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
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
     * TODO @JT change documentation
     *
     * @param loginRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildHomeTokenAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return HOME token used to access restricted resources offered in SymbIoTe
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
    ValidationStatus validateCoupon(String coupon) throws AAMException;
}
