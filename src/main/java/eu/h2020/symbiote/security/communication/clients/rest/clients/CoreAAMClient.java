package eu.h2020.symbiote.security.communication.clients.rest.clients;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

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
    public Map<String, AAM> getAvailableAAMs() throws SecurityHandlerException {
        Map<String, AAM> aams;
        log.debug("Trying to fetch available AAMs from Core AAM");

        // TODO possibly rework to use Feign client
        RestTemplate restTemplate = new RestTemplate();

        ResponseEntity<Map<String, AAM>> response = restTemplate.exchange(getURL() + SecurityConstants
                .AAM_GET_AVAILABLE_AAMS, HttpMethod.GET, null, new ParameterizedTypeReference<Map<String, AAM>>() {
        });
        if (response.getStatusCode() == HttpStatus.OK)
            aams = response.getBody();
        else
            throw new SecurityHandlerException("Failed to retrieve available security entry points from Symbiote Core AAM");
        return aams;
    }

}
