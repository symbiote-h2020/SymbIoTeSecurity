package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.interfaces.IFeignAAMClient;
import eu.h2020.symbiote.security.communication.payloads.*;
import feign.Feign;
import feign.Response;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;

import java.util.Optional;

/**
 * Crude RMI-like client's implementation to the AAM module that communicates with it over REST.
 *
 * @author Dariusz Krajewski (PSNC)
 */
public class AAMClient implements IAAMClient {

    private String serverAddress;
    private IFeignAAMClient feignClient;

    /**
     * @param serverAddress of the AAM server the client wants to interact with.
     */
    public AAMClient(String serverAddress) {
        this.serverAddress = serverAddress;
        this.feignClient = getJsonClient();
    }

    /**
     * @return Instance of feign client with all necessary parameters set
     */
    private IFeignAAMClient getJsonClient() {
        return Feign.builder().encoder(new JacksonEncoder()).decoder(new JacksonDecoder())
                .target(IFeignAAMClient.class, serverAddress);
    }

    /**
     * @return Certificate of the component in PEM format. In this case the AAM certificate.
     */
    @Override
    public String getComponentCertificate() throws AAMException {
        Response response = feignClient.getComponentCertificate();
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
    @Override
    public String getClientCertificate(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            InvalidArgumentsException {
        Response response = feignClient.getClientCertificate(certificateRequest);
        switch (response.status()) {
            case 400:
                if (response.body().toString().contains("INVALID_ARGUMENTS"))
                    throw new InvalidArgumentsException(response.body().toString());
                throw new NotExistingUserException(response.body().toString());
            case 401:
                //TODO: Find a way to differentiate ValidationException from WrongCredentialsException since response's body is empty on error
                throw new ValidationException("Could not validate - Invalid certificate / credentials");
            default:
                return response.body().toString();
        }

    }

    /**
     * Allows the user to revoke their credentials
     * @param revocationRequest required to revoke a certificate or token.
     * @return the signed certificate from the provided CSR in PEM format
     */
    @Override
    public String revoke(RevocationRequest revocationRequest) throws InvalidArgumentsException, WrongCredentialsException {
        Response response = feignClient.revoke(revocationRequest);
        switch (response.status()) {
            case 400:
                throw new InvalidArgumentsException(response.body().toString());
            case 401:
                throw new WrongCredentialsException();
            default:
                return response.body().toString();
        }

    }

    /**
     * @return GUEST token used to access public resources offered in SymbIoTe
     */
    @Override
    public String getGuestToken() throws JWTCreationException {
        Response response = feignClient.getGuestToken();
        if (response.status() == 500)
            throw new JWTCreationException("Server failed to create a guest token");
        return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toString();
    }

    /**
     * @param loginRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildHomeTokenAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return HOME token used to access restricted resources offered in SymbIoTe
     */
    @Override
    public String getHomeToken(String loginRequest) throws
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException {
        Response response = feignClient.getHomeToken(loginRequest);
        switch (response.status()) {
            case 400:
                throw new MalformedJWTException("Unable to read malformed token");
            case 401:
                throw new WrongCredentialsException("Could not validate token with incorrect credentials");
            case 500:
                throw new JWTCreationException("Server failed to create a home token");
            default:
                return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toArray()[0].toString();
        }
    }

    /**
     * @param remoteHomeToken   that an actor wants to exchange in this AAM for a FOREIGN token
     * @param clientCertificate in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param aamCertificate    in PEM with key matching the IPK claim in the provided token in 'offline' (intranet) scenarios
     * @return FOREIGN token used to access restricted resources offered in SymbIoTe federations
     */
    @Override
    public String getForeignToken(String remoteHomeToken, Optional<String> clientCertificate, Optional<String> aamCertificate) throws
            ValidationException,
            JWTCreationException {
        Response response = feignClient.getForeignToken(remoteHomeToken, clientCertificate.orElse(""), aamCertificate.orElse(""));
        switch (response.status()) {
            case 401:
                throw new ValidationException("Failed to validate homeToken");
            case 500:
                throw new JWTCreationException("Server failed to create a foreign token");
            default:
                return response.headers().get(SecurityConstants.TOKEN_HEADER_NAME).toArray()[0].toString();
        }

    }

    /**
     * @return collection of AAMs available in the SymbIoTe ecosystem
     */
    @Override
    public AvailableAAMsCollection getAvailableAAMs() {
        return feignClient.getAvailableAAMs();
    }

    /**
     * @param token                                  that is to be validated
     * @param clientCertificate                      in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param clientCertificateSigningAAMCertificate in PEM being the AAM that signed the clientCertificate  in 'offline' (intranet) scenarios
     * @param foreignTokenIssuingAAMCertificate      in PEM with key matching the IPK claim in the provided FOREIGN token in 'offline' (intranet) scenarios
     * @return validation status
     */
    @Override
    public ValidationStatus validate(String token, Optional<String> clientCertificate, Optional<String> clientCertificateSigningAAMCertificate, Optional<String> foreignTokenIssuingAAMCertificate) {
        return feignClient.validate(token, clientCertificate.orElse(""), clientCertificateSigningAAMCertificate.orElse(""), foreignTokenIssuingAAMCertificate.orElse(""));
    }

    /**
     * @param platformManagementRequest related to associated platforms' management operation.
     * @return Management Status informing about a result of completing requested management operation
     */
    @Override
    public ManagementStatus manage(PlatformManagementRequest platformManagementRequest) throws AAMException {
        try {
            return feignClient.manage(platformManagementRequest).getRegistrationStatus();
        } catch (Exception e) {
            throw new AAMException("Internal Platform Management Error");
        }
    }

    /**
     * @param userManagementRequest  related to associated users' management operation.
     * @return Management Status informing about a result of completing requested management operation
     */
    @Override
    public ManagementStatus manage(UserManagementRequest userManagementRequest) throws AAMException {
        try {
            return feignClient.manage(userManagementRequest);
        } catch (Exception e) {
            throw new AAMException("Internal User Management Error");
        }
    }

}
