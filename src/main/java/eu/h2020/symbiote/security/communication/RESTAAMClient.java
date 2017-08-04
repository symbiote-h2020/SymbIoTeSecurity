package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.communication.interfaces.FeignAAMRESTInterface;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import feign.Feign;
import feign.Headers;
import feign.Response;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

/**
 * For response handling (WIP)
 *
 * @author Dariusz Krajewski (PSNC)
 */
public class RESTAAMClient {

    private String serveraddress;
    private FeignAAMRESTInterface restaamClient;
    private int status;
    //  Required by some tests
    private Headers headers;
    private Response.Body body;

    //*********
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

    public String getComponentCertificate() {
        Response response = restaamClient.getComponentCertificate();
        this.status = response.status();
        return response.body().toString();
    }

    public Response.Body getBody() {
        return body;
    }

    public String getClientCertificate(CertificateRequest certRequest) {
        Response response = restaamClient.getClientCertificate(certRequest);
        this.status = response.status();
        this.body = response.body();
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
        try {
            return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toArray()[0].toString();
        } catch (NullPointerException e) {
            return response.headers().toString();
        }
    }

    public String getForeignToken(HttpEntity<String> entity, String certificate) throws HttpClientErrorException, HttpServerErrorException {
        Response response = restaamClient.getForeignToken(entity.getHeaders()
                .get(SecurityConstants.TOKEN_HEADER_NAME)
                .toArray()[0].toString(), certificate);
        if (response.status() >= 400 && response.status() < 500)
            throw new HttpClientErrorException(HttpStatus.valueOf(response.status()));
        else if (response.status() >= 500) throw new HttpServerErrorException(HttpStatus.valueOf(response.status()));
        this.status = response.status();
        return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toArray()[0].toString();

    }

    public AvailableAAMsCollection getAvailableAAMs() {
        return restaamClient.getAvailableAAMs();
    }

    public ValidationStatus validate(String token, String certificate) {
        return restaamClient.validate(token, certificate);
    }

}
