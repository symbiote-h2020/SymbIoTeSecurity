package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
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

    public RESTAAMClient(String serverAddress) {
        this.serverAddress = serverAddress;
        this.aamClient = getJsonClient();
    }

    private FeignAAMRESTInterface getJsonClient() {
        return Feign.builder().encoder(new JacksonEncoder()).decoder(new JacksonDecoder())
                .target(FeignAAMRESTInterface.class, serverAddress);
    }

    /**
     * @return Certificate of the component in PEM format
     */
    public String getComponentCertificate() {
        Response response = aamClient.getComponentCertificate();
        return response.body().toString();
    }

    /**
     * Exposes a service that allows users to acquire their client certificates.
     *
     * @param certificateRequest required to issue a certificate for given (username, clientId) tupple.
     * @return the certificate issued using the provided CSR in PEM format
     */
    public String getClientCertificate(CertificateRequest certificateRequest) throws WrongCredentialsException, NotExistingUserException,
            ValidationException, InvalidArgumentsException, SecurityException {
        Response response = aamClient.getClientCertificate(certificateRequest);
        if (response.status() == 400)
            throw new InvalidArgumentsException(response.body().toString());
        return response.body().toString();
    }

    /**
     * @return GUEST token used to access public resources offered in SymbIoTe
     */
    public String getGuestToken() throws JWTCreationException {
        Response response = aamClient.getGuestToken();
        if (response.status() == 500)
            throw new JWTCreationException("Server failed to create a foreign token");
        return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toString();
    }

    /**
     * @param loginRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildHomeTokenAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return HOME token used to access restricted resources offered in SymbIoTe
     */
    public String getHomeToken(String loginRequest) throws WrongCredentialsException, JWTCreationException {
        Response response = aamClient.getHomeToken(loginRequest);
        switch (response.status()) {
            case 401:
                throw new WrongCredentialsException("Could not validate token with incorrect credentials");
            case 500:
                throw new WrongCredentialsException("Server failed to create a foreign token");
        }
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
        switch (response.status()) {
            case 401:
                throw new ValidationException("Failed to validate homeToken");
            case 500:
                throw new JWTCreationException("Server failed to create a foreign token");
        }
        return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toArray()[0].toString();
    }

    /**
     * @return collection of AAMs available in the SymbIoTe ecosystem
     */
    public AvailableAAMsCollection getAvailableAAMs() {
        return aamClient.getAvailableAAMs();
    }

    /**
     * @param token       that is to be validated
     * @param certificate matching the SPK from the token
     * @return validation status
     */
    public ValidationStatus validate(String token, String certificate) {
        return aamClient.validate(token, certificate);
    }

}
