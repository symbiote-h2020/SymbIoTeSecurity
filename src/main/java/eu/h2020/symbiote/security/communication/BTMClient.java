package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.interfaces.IFeignBTMClient;
import eu.h2020.symbiote.security.communication.payloads.BarteredAccessRequest;
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
 * Crude RMI-like client's implementation to the Bartering and Trading  module that communicates with it over REST.
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
     * Ask for authorization of the bartered access,
     * @param barteredAccessRequest request containing information about client's platform, resource Id and type of access
     * @return information if access is granted
     */
    @Override
    public boolean authorizeBarteredAccess(BarteredAccessRequest barteredAccessRequest) throws BTMException {
        Response response;
        try {
            response = feignClient.authorizeBarteredAccess(barteredAccessRequest);
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        switch (response.status()) {
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
            couponString = feignClient.getCoupon(couponRequest).body().toString();
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        return couponString;
    }


}
