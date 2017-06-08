package eu.h2020.symbiote.security.rest.clients;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.session.AAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.List;

/**
 * Client for Core AAM services exposed over Symbiote Core Interface
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class CoreAAMClient extends AAMClient {
    private static final Log log = LogFactory.getLog(CoreAAMClient.class);

    /**
     * Used to create the main symbiote security entry point.
     *
     * @param symbioteCoreInterfaceAddress this address will be available to public once SymbIoTe is production ready.
     */
    public CoreAAMClient(String symbioteCoreInterfaceAddress) {
        createClient(symbioteCoreInterfaceAddress);
    }

    /**
     * @return list of all currently available security entrypoints to symbiote (login, token (request, validation))
     * for Release 2 with Core certificate, for R3 will include Platforms' certificates
     * @throws SecurityHandlerException on operation error
     */
    public List<AAM> getAvailableAAMs() throws SecurityHandlerException {
        List<AAM> aams;
        log.debug("Trying to fetch available AAMs from Core AAM");

        // TODO possibly rework to use Feign client
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<List<AAM>> response = restTemplate.exchange(
                getURL() + AAMConstants.AAM_GET_AVAILABLE_AAMS,
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<List<AAM>>() {
                });
        if (response.getStatusCode() == HttpStatus.OK)
            aams = response.getBody();
        else
            throw new SecurityHandlerException("Failed to retrieve available security entry points from Symbiote Core AAM");
        return aams;
    }

}

