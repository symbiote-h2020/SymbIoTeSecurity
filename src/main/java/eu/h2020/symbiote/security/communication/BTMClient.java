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

    private static final String AAM_COMMS_ERROR_MESSAGE = "Failed to communicate with the AAM: ";
    private String serverAddress;
    private IFeignBTMClient feignClient;

    /**
     * @param serverAddress of the AAM server the client wants to interact with.
     */
    public BTMClient(String serverAddress) {
        this(serverAddress, new ApacheCommonsLogger4Feign(logger));
    }

    /**
     * @param serverAddress of the AAM server the client wants to interact with.
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
            AAMException {
        Response response;
        try {
            response = feignClient.revokeCoupon(revocationRequest);
        } catch (FeignException fe) {
            //TODO @JT change error messages
            throw new AAMException(AAM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        switch (response.status()) {
            case 400:
                throw new InvalidArgumentsException(response.body().toString());
            case 401:
                throw new WrongCredentialsException();
            case 200:
                if (response.body().toString().isEmpty()) {
                    throw new AAMException("Error occured. Response is empty!");
                }
                return response.body().toString();
            default:
                throw new AAMException("Error occured. Error code: " + response.status() + ". Message: " + response.body().toString());
        }

    }

    @Override
    public boolean consumeCoupon(String coupon) throws AAMException, MalformedJWTException, WrongCredentialsException, JWTCreationException {
        Response response;
        try {
            response = feignClient.consumeCoupon(coupon);
        } catch (FeignException fe) {
            //TODO @JT change error msg
            throw new AAMException(AAM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        switch (response.status()) {
            case 400:
                throw new MalformedJWTException("Unable to read malformed coupon");
            case 401:
                throw new WrongCredentialsException("Could not validate coupon with incorrect credentials");
            case 500:
                throw new JWTCreationException("Server failed use coupon");
            case 200:
                return true;
            default:
                throw new AAMException("Error occured. Error code: " + response.status() + ". Message: " + response.body().toString());
        }
    }

    /**
     * TODO @JT change documentation
     *
     * @param loginRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildJWTAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return HOME token used to access restricted resources offered in SymbIoTe
     */
    @Override
    public String getDiscreteCoupon(String loginRequest) throws
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException,
            AAMException {
        Response response;
        try {
            response = feignClient.getDiscreteCoupon(loginRequest);
        } catch (FeignException fe) {
            //TODO @JT change error msg
            throw new AAMException(AAM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        switch (response.status()) {
            case 400:
                throw new MalformedJWTException("Unable to read malformed request");
            case 401:
                throw new WrongCredentialsException("Could not validate request with incorrect credentials");
            case 500:
                throw new JWTCreationException("Server failed to create a coupon");
            case 200:
                //TODO change this
                Collection headers = response.headers().get(SecurityConstants.COUPON_HEADER_NAME);
                if (headers == null ||
                        headers.toArray().length == 0) {
                    //TODO @JT change error msg
                    throw new AAMException(AAMException.NO_TOKEN_IN_RESPONSE);
                }
                return headers.toArray()[0].toString();
            default:
                throw new AAMException("Error occured. Error code: " + response.status() + ". Message: " + response.body().toString());
        }
    }

    /**
     * @param coupon that is to be validated
     * @return validation status
     */
    @Override
    public CouponValidationStatus validateCoupon(String coupon) throws
            AAMException {
        try {
            return feignClient.validateCoupon(coupon);
        } catch (FeignException fe) {
            //TODO @JT change error msg
            throw new AAMException(AAM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
    }
}
