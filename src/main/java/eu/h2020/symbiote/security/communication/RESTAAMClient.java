package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.interfaces.FeignAAMRESTInterface;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import feign.Feign;
import feign.FeignException;
import feign.Response;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import org.springframework.http.HttpEntity;

/**
 * For response handling (WIP)
 *
 * @author Dariusz Krajewski (PSNC)
 */
public class RESTAAMClient {

    private String serveraddress;
    private FeignAAMRESTInterface restaamClient;
    private int status;

    public RESTAAMClient(String serveraddress) {
        this.serveraddress = serveraddress;
        this.restaamClient = getJsonClient();
    }

    private FeignAAMRESTInterface getJsonClient() {
        return Feign.builder().encoder(new JacksonEncoder()).decoder(new JacksonDecoder())
                .target(FeignAAMRESTInterface.class, serveraddress);
    }

    public int getStatus() {
        return status;
    }

    public String getClientCertificate(CertificateRequest certRequest) {
        Response response = restaamClient.getClientCertificate(certRequest);
        this.status = response.status();
        return response.body().toString();
    }

    public String getGuestToken() {
        Response response = restaamClient.getGuestToken();
        this.status = response.status();
        return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toString();
    }

    public String getHomeToken(String loginRequest) {
        Response response = restaamClient.getHomeToken(loginRequest);
        this.status = response.status();
        return response.headers().toString();
    }

    public String getForeignToken(HttpEntity<String> entity, String certificate) throws FeignException {
        Response response = restaamClient.getForeignToken(entity.getHeaders()
                .get(SecurityConstants.TOKEN_HEADER_NAME)
                .toArray()[0].toString(), certificate);
        this.status = response.status();
        return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toArray()[0].toString();
    }


}
