package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.*;

import java.util.Optional;

/**
 * Crude RMI-like client's interface to the AAM module.
 *
 * @author Dariusz Krajewski (PSNC)
 * @author Mikolaj Dobski (PSNC)
 */
public interface IAAMClient {
    /**
     * @return Certificate of the component in PEM format. In this case the AAM certificate.
     */
    String getComponentCertificate() throws AAMException;

    /**
     * Allows the user to acquire their client's certificate.
     *
     * @param certificateRequest required to issue a certificate for given (username, clientId) tupple.
     * @return the signed certificate from the provided CSR in PEM format
     */
    String getClientCertificate(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            InvalidArgumentsException;

    /**
     * Allows the user to revoke their credentials
     *
     * @param revocationRequest required to revoke a certificate or token.
     * @return the signed certificate from the provided CSR in PEM format
     */
    String revoke(RevocationRequest revocationRequest) throws InvalidArgumentsException, WrongCredentialsException;

    /**
     * @return GUEST token used to access public resources offered in SymbIoTe
     */
    String getGuestToken() throws JWTCreationException;

    /**
     * @param loginRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildHomeTokenAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return HOME token used to access restricted resources offered in SymbIoTe
     */
    String getHomeToken(String loginRequest) throws
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException;

    /**
     * @param remoteHomeToken   that an actor wants to exchange in this AAM for a FOREIGN token
     * @param clientCertificate in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param aamCertificate    in PEM with key matching the IPK claim in the provided token in 'offline' (intranet) scenarios
     * @return FOREIGN token used to access restricted resources offered in SymbIoTe federations
     */
    String getForeignToken(String remoteHomeToken, Optional<String> clientCertificate, Optional<String> aamCertificate) throws
            ValidationException,
            JWTCreationException;

    /**
     * @return collection of AAMs available in the SymbIoTe ecosystem
     */
    AvailableAAMsCollection getAvailableAAMs();

    /**
     * @param token                                  that is to be validated
     * @param clientCertificate                      in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param clientCertificateSigningAAMCertificate in PEM being the AAM that signed the clientCertificate  in 'offline' (intranet) scenarios
     * @param foreignTokenIssuingAAMCertificate      in PEM with key matching the IPK claim in the provided FOREIGN token in 'offline' (intranet) scenarios
     * @return validation status
     */
    ValidationStatus validate(String token, Optional<String> clientCertificate, Optional<String> clientCertificateSigningAAMCertificate, Optional<String> foreignTokenIssuingAAMCertificate);

    /**
     * @param platformManagementRequest related to associated platforms' management operation.
     * @return Management Status informing about a result of completing requested management operation
     */
    ManagementStatus manage(PlatformManagementRequest platformManagementRequest) throws AAMException;

    /**
     * @param userManagementRequest related to associated users' management operation.
     * @return Management Status informing about a result of completing requested management operation
     */
    ManagementStatus manage(UserManagementRequest userManagementRequest) throws AAMException;

    /**
     * @param credentials of a user whose details should be returned
     * @return details of requested user
     */
    UserDetails getUserDetails(Credentials credentials) throws UserManagementException;
}
