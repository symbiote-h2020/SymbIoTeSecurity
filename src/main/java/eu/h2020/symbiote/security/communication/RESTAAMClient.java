package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.interfaces.FeignAAMRESTInterface;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import feign.Feign;
import feign.Response;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;

/**
 * For response handling (WIP)
 *
 * @author Dariusz Krajewski (PSNC)
 */
public class RESTAAMClient {

    private String serverAddress;
    private FeignAAMRESTInterface aamClient;
    private int status;
    private Response.Body body;

    //*********
    public RESTAAMClient(String serverAddress) {
        this.serverAddress = serverAddress;
        this.aamClient = getJsonClient();
    }

    private FeignAAMRESTInterface getJsonClient() {
        return Feign.builder().encoder(new JacksonEncoder()).decoder(new JacksonDecoder())
                .target(FeignAAMRESTInterface.class, serverAddress);
    }

    public int getStatus() {
        return status;
    }

    public String getComponentCertificate() {
        Response response = aamClient.getComponentCertificate();
        this.status = response.status();
        return response.body().toString();
    }

    public Response.Body getBody() {
        return body;
    }

    public String getClientCertificate(CertificateRequest certRequest) {
        Response response = aamClient.getClientCertificate(certRequest);
        this.status = response.status();
        this.body = response.body();
        return response.body().toString();
    }

    public String getGuestToken() {
        Response response = aamClient.getGuestToken();
        this.status = response.status();
        return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toString();
    }

    public String getHomeToken(String loginRequest) {
        Response response = aamClient.getHomeToken(loginRequest);
        this.status = response.status();
        try {
            return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toArray()[0].toString();
        } catch (NullPointerException e) {
            return response.headers().toString();
        }
    }

    /**
     * @param remoteHomeToken that an actor wants to exchange in this AAM for a FOREIGN token
     * @param certificate     matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @return FOREIGN token used to access restricted resources offered in SymbIoTe federations
     */
    public String getForeignToken(String remoteHomeToken, String certificate) throws ValidationException,
            JWTCreationException {
        Response response = aamClient.getForeignToken(remoteHomeToken, certificate);
        // todo check what exceptions are thrown with what codes and handle them explicitly
        if (response.status() >= 400 && response.status() < 500)
            throw new ValidationException("Failed to validate homeToken");
        else if (response.status() >= 500) throw new JWTCreationException("Server failed to create a foreign token");
        this.status = response.status();
        return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toArray()[0].toString();

    }

    public AvailableAAMsCollection getAvailableAAMs() {
        return aamClient.getAvailableAAMs();
    }

    public ValidationStatus validate(String token, String certificate) {
        return aamClient.validate(token, certificate);
    }

}
