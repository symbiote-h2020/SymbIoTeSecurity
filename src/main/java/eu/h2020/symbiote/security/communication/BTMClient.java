package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.interfaces.IFeignBTMClient;
import eu.h2020.symbiote.security.communication.payloads.BarteralAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
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
     * Allows registering coupon in the Core BTM."
     *@param couponString to register
     *@return status of the operation (true - success)
     */
    @Override
    public boolean registerCoupon(String couponString) throws BTMException {
        Response response;
        try {
            response = feignClient.registerCoupon(couponString);
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        switch (response.status()) {
            //TODO other cases
            case 200:
                return true;
            default:
                throw new BTMException(ERROR_OCCURED_ERROR_CODE + response.status() + MESSAGE + response.body().toString());
        }
    }

    /**
     * Coupon validation in Core BTM
     *
     * @param couponString for validation
     * @return couponValidity containing information about remaining usages/time and validation status
     */
    @Override
    public CouponValidity isCouponValid(String couponString) throws BTMException {
        CouponValidity couponValidity;
        try {
            couponValidity = feignClient.isCouponValid(couponString);
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        return couponValidity;
    }

    /**
     * Coupon consumption in the Core BTM
     *
     * @param couponString for consumption
     * @return consumption status (true - success)
     */
    @Override
    public boolean consumeCoupon(String couponString) throws BTMException {
        Response response;
        try {
            response = feignClient.consumeCoupon(couponString);
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        switch (response.status()) {
            //TODO other cases
            case 200:
                return true;
            default:
                throw new BTMException(ERROR_OCCURED_ERROR_CODE + response.status() + MESSAGE + response.body().toString());
        }
    }

    /**
     * Ask for authorization of the barteral access
     * @param barteralAccessRequest request containing information about client's platform, resource Id and type of access
     * @return information if access is granted
     */
    @Override
    public boolean authorizeBarteralAccess(BarteralAccessRequest barteralAccessRequest) throws BTMException {
        Response response;
        try {
            response = feignClient.authorizeBarteralAccess(barteralAccessRequest);
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        switch (response.status()) {
            //TODO other cases
            case 200:
                return true;
            default:
                throw new BTMException(ERROR_OCCURED_ERROR_CODE + response.status() + MESSAGE + response.body().toString());
        }
    }

    /**
     * asks BTM for coupon to access the resource
     *
     * @param couponRequest request containing information about platform, type of access
     * @return Coupon coupon
     */
    @Override
    public String getCoupon(CouponRequest couponRequest) throws BTMException {
        String couponString;
        try {
            couponString = feignClient.getCoupon(couponRequest);
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        return couponString;
    }


}
