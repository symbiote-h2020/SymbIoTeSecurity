package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.interfaces.IFeignBTMClient;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import feign.Feign;
import feign.FeignException;
import feign.Logger;
import feign.Logger.Level;
import feign.Response;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Collection;

/**
 * Crude RMI-like client's implementation to the Bartening and Trading  module that communicates with it over REST.
 *
 * @author Jakub Toczek (PSNC)
 */
public class BTMClient implements IBTMClient {
    private static final Log logger = LogFactory.getLog(BTMClient.class);

    private static final String BTM_COMMS_ERROR_MESSAGE = "Failed to communicate with the BTM: ";
    private static final String ERROR_OCCURED_ERROR_CODE = "Error occured. Error code: ";
    private static final String MESSAGE = ". Message: ";
    private String serverAddress;
    private IFeignBTMClient feignClient;

    /**
     * @param serverAddress of the BTM server the client wants to interact with.
     */
    public BTMClient(String serverAddress) {
        this(serverAddress, new ApacheCommonsLogger4Feign(logger));
    }

    /**
     * @param serverAddress of the BTM server the client wants to interact with.
     * @param logger        feign logger
     */
    public BTMClient(String serverAddress, Logger logger) {
        this.serverAddress = serverAddress;
        this.feignClient = getJsonClient(logger);
    }

    /**
     * @return Instance of feign client with all necessary parameters set
     */
    private IFeignBTMClient getJsonClient(Logger logger) {
        return Feign.builder()
                .encoder(new JacksonEncoder())
                .decoder(new JacksonDecoder())
                .logger(logger)
                .logLevel(Level.FULL)
                .target(IFeignBTMClient.class, serverAddress);
    }

    /**
     * Allows the user to revoke their coupons
     *
     * @param revocationRequest required to revoke a coupon.
     * @return revocation status
     */
    @Override
    public String revokeCoupon(RevocationRequest revocationRequest) throws
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException {
        Response response;
        try {
            response = feignClient.revokeCoupon(revocationRequest);
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        switch (response.status()) {
            case 400:
                throw new InvalidArgumentsException(response.body().toString());
            case 401:
                throw new WrongCredentialsException();
            case 200:
                if (response.body().toString().isEmpty()) {
                    throw new BTMException(BTMException.RESPONSE_IS_EMPTY);
                }
                return response.body().toString();
            default:
                throw new BTMException(ERROR_OCCURED_ERROR_CODE + response.status() + MESSAGE + response.body().toString());
        }

    }

    /**
     * Allows the user to use the coupon to get access to another federated platform’s data under a bartering scenario
     *
     * @param coupon - valid coupon to consume
     * @return true if consumed properly
     */
    @Override
    public boolean consumeCoupon(String coupon) throws
            MalformedJWTException,
            WrongCredentialsException,
            JWTCreationException,
            BTMException {
        Response response;
        try {
            response = feignClient.consumeCoupon(coupon);
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        switch (response.status()) {
            case 400:
                throw new MalformedJWTException(MalformedJWTException.UNABLE_TO_READ_MALFORMED_COUPON);
            case 401:
                throw new WrongCredentialsException(WrongCredentialsException.COUPON_WITH_INCORRECT_CREDENTIALS);
            case 500:
                throw new JWTCreationException(JWTCreationException.SERVER_FAILED_USE_COUPON);
            case 200:
                return true;
            default:
                throw new BTMException(ERROR_OCCURED_ERROR_CODE + response.status() + MESSAGE + response.body().toString());
        }
    }

    /**
     * TODO @JT change documentation
     *
     * @param couponRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildJWTAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return coupon to access another federated platform’s data under a bartering scenario
     */
    @Override
    public String getDiscreteCoupon(String couponRequest) throws
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException,
            BTMException {
        Response response;
        try {
            response = feignClient.getDiscreteCoupon(couponRequest);
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        switch (response.status()) {
            case 400:
                throw new MalformedJWTException(MalformedJWTException.UNABLE_TO_READ_MALFORMED_COUPON);
            case 401:
                throw new WrongCredentialsException(WrongCredentialsException.COUPON_WITH_INCORRECT_CREDENTIALS);
            case 500:
                throw new JWTCreationException(JWTCreationException.SERVER_FAILED_USE_COUPON);
            case 200:
                Collection headers = response.headers().get(SecurityConstants.COUPON_HEADER_NAME);
                if (headers == null ||
                        headers.toArray().length == 0) {
                    throw new BTMException(BTMException.NO_COUPON_IN_RESPONSE);
                }
                return headers.toArray()[0].toString();
            default:
                throw new BTMException(ERROR_OCCURED_ERROR_CODE + response.status() + MESSAGE + response.body().toString());
        }
    }

    /**
     * Allows the user to validate coupon
     * @param coupon for validation
     * @return validation status
     */
    @Override
    public CouponValidationStatus validateCoupon(String coupon) throws
            BTMException {
        try {
            return feignClient.validateCoupon(coupon);
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
    }
}
