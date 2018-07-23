package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.interfaces.IFeignBTMComponentClient;
import eu.h2020.symbiote.security.communication.payloads.BarteredAccessRequest;
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
public class BTMComponentClient implements IBTMComponentClient {
    private static final Log logger = LogFactory.getLog(BTMComponentClient.class);

    private static final String BTM_COMMS_ERROR_MESSAGE = "Failed to communicate with the BTM: ";
    private static final String ERROR_OCCURED_ERROR_CODE = "Error occured. Error code: ";
    private static final String MESSAGE = ". Message: ";
    private String serverAddress;
    private IFeignBTMComponentClient feignClient;

    /**
     * @param serverAddress of the BTM server the client wants to interact with.
     */
    public BTMComponentClient(String serverAddress) {
        this(serverAddress, new ApacheCommonsLogger4Feign(logger));
    }

    /**
     * @param serverAddress of the BTM server the client wants to interact with.
     * @param logger        feign logger
     */
    public BTMComponentClient(String serverAddress, Logger logger) {
        this.serverAddress = serverAddress;
        this.feignClient = getJsonClient(logger);
    }

    /**
     * @return Instance of feign client with all necessary parameters set
     */
    private IFeignBTMComponentClient getJsonClient(Logger logger) {
        return Feign.builder()
                .encoder(new JacksonEncoder())
                .decoder(new JacksonDecoder())
                .logger(logger)
                .logLevel(Level.FULL)
                .target(IFeignBTMComponentClient.class, serverAddress);
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
}
