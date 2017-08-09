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

import java.util.Optional;

/**
 * Crude RMI-like client to the AAM module that communicates with it over REST.
 *
 * @author Dariusz Krajewski (PSNC)
 */
public class RESTAAMClient {

    private String serverAddress;
    private FeignAAMRESTInterface aamClient;

    /**
     * @param serverAddress of the AAM server the client wants to interact with.
     */
    public RESTAAMClient(String serverAddress) {
        this.serverAddress = serverAddress;
        this.aamClient = getJsonClient();
    }

    /**
     * @return Instance of feign client with all necessary parameters set
     */
    private FeignAAMRESTInterface getJsonClient() {
        return Feign.builder().encoder(new JacksonEncoder()).decoder(new JacksonDecoder())
                .target(FeignAAMRESTInterface.class, serverAddress);
    }

    /**
     * @return Certificate of the component in PEM format. In this case the AAM certificate.
     */
    public String getComponentCertificate() throws AAMException {
        Response response = aamClient.getComponentCertificate();
        if (response.status() == 500)
            throw new AAMException(response.body().toString());
        return response.body().toString();
    }

    /**
     * Allows the user to acquire their client's certificate.
     *
     * @param certificateRequest required to issue a certificate for given (username, clientId) tupple.
     * @return the signed certificate from the provided CSR in PEM format
     */
    public String getClientCertificate(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            InvalidArgumentsException {
        Response response = aamClient.getClientCertificate(certificateRequest);
        switch (response.status()) {
            case 400:
                if (response.body().toString().contains("INVALID_ARGUMENTS"))
                    throw new InvalidArgumentsException(response.body().toString());
                throw new NotExistingUserException(response.body().toString());
            case 401:
                //TODO: Find a way to differentiate ValidationException from WrongCredentialsException since response's body is empty on error
                throw new ValidationException("Could not validate - Invalid certificate / credentials");
        }
        return response.body().toString();
    }

    /**
     * @return GUEST token used to access public resources offered in SymbIoTe
     */
    public String getGuestToken() throws JWTCreationException {
        Response response = aamClient.getGuestToken();
        if (response.status() == 500)
            throw new JWTCreationException("Server failed to create a guest token");
        return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toString();
    }

    /**
     * @param loginRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildHomeTokenAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return HOME token used to access restricted resources offered in SymbIoTe
     */
    public String getHomeToken(String loginRequest) throws
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException {
        Response response = aamClient.getHomeToken(loginRequest);
        switch (response.status()) {
            case 400:
                throw new MalformedJWTException("Unable to read malformed token");
            case 401:
                throw new WrongCredentialsException("Could not validate token with incorrect credentials");
            case 500:
                throw new JWTCreationException("Server failed to create a home token");
        }
        return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toArray()[0].toString();
    }

    /**
     * @param remoteHomeToken   that an actor wants to exchange in this AAM for a FOREIGN token
     * @param clientCertificate in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param aamCertificate    in PEM with key matching the IPK claim in the provided token in 'offline' (intranet) scenarios
     * @return FOREIGN token used to access restricted resources offered in SymbIoTe federations
     */
    public String getForeignToken(String remoteHomeToken, Optional<String> clientCertificate, Optional<String> aamCertificate) throws
            ValidationException,
            JWTCreationException {
        Response response = aamClient.getForeignToken(remoteHomeToken, clientCertificate.orElse(""), aamCertificate.orElse(""));
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
     * @param token             that is to be validated
     * @param clientCertificate in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param aamCertificate    in PEM with key matching the IPK claim in the provided token in 'offline' (intranet) scenarios
     * @return validation status
     */
    public ValidationStatus validate(String token, Optional<String> clientCertificate, Optional<String> aamCertificate) {
        return aamClient.validate(token, clientCertificate.orElse(""), aamCertificate.orElse(""));
    }

}
