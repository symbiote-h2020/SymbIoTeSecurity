package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.exceptions.custom.ADMException;
import eu.h2020.symbiote.security.communication.interfaces.IFeignADMClient;
import eu.h2020.symbiote.security.communication.payloads.FailedFederationAuthorizationReport;
import feign.Feign;
import feign.FeignException;
import feign.Logger;
import feign.Logger.Level;
import feign.Response;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static eu.h2020.symbiote.security.commons.exceptions.custom.ADMException.ADM_NOT_AVAILABLE;

/**
 * Crude RMI-like client's implementation to the Anomaly Detection Module module that communicates with it over REST.
 *
 * @author Jakub Toczek (PSNC)
 */
public class ADMClient implements IADMClient {
    private static final Log logger = LogFactory.getLog(ADMClient.class);

    private static final String ADM_COMMS_ERROR_MESSAGE = "Failed to communicate with the Anomaly Detection Module: ";
    private String serverAddress;
    private IFeignADMClient feignClient;

    /**
     * @param serverAddress of the Anomaly Detection Module server the client wants to interact with.
     */
    public ADMClient(String serverAddress) {
        this(serverAddress, new ApacheCommonsLogger4Feign(logger));
    }

    /**
     * @param serverAddress of the Anomaly Detection Module server the client wants to interact with.
     * @param logger        feign logger
     */
    public ADMClient(String serverAddress, Logger logger) {
        this.serverAddress = serverAddress;
        this.feignClient = getJsonClient(logger);
    }

    /**
     * @return Instance of feign client with all necessary parameters set
     */
    private IFeignADMClient getJsonClient(Logger logger) {
        return Feign.builder()
                .encoder(new JacksonEncoder())
                .decoder(new JacksonDecoder())
                .logger(logger)
                .logLevel(Level.FULL)
                .target(IFeignADMClient.class, serverAddress);
    }

    /**
     * @param report report to be sent
     * @return true if anomaly saved
     */
    @Override
    public boolean reportFailedFederatedAuthorization(FailedFederationAuthorizationReport report) throws
            ADMException {
        Response response;
        try {
            response = feignClient.reportFailedFederatedAuthorization(report);
        } catch (FeignException fe) {
            throw new ADMException(ADM_NOT_AVAILABLE);
        }
        switch (response.status()) {
            case 200:
                return true;
            case 400: //Bad Request
                throw new ADMException("Provided report is missing some values");
            case 401: //Error 401 - Unauthorized
                throw new ADMException("Provided Security Request does not give access to this resource");
            default:
                throw new ADMException("Internal server error");
        }
    }
}
