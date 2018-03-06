package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.SecurityConstants;
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
     * @param componentIdentifier component identifier or {@link SecurityConstants#AAM_COMPONENT_NAME} for AAM CA certificate
     * @param platformIdentifier  for a platform component or {@link SecurityConstants#CORE_AAM_INSTANCE_ID} for Symbiote core components
     * @return symbiote component Certificate of the component in PEM format
     */
    String getComponentCertificate(String componentIdentifier,
                                   String platformIdentifier) throws
            AAMException;

    /**
     * Allows the user to acquire their client's certificate.
     *
     * @param certificateRequest required to issue a certificate for given (username, clientId) tupple.
     * @return the signed certificate from the provided CSR in PEM format
     */
    String signCertificateRequest(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            InvalidArgumentsException,
            AAMException;

    /**
     * Allows the user to revoke their credentials
     *
     * @param revocationRequest required to revoke a certificate or token.
     * @return the signed certificate from the provided CSR in PEM format
     */
    String revokeCredentials(RevocationRequest revocationRequest) throws
            InvalidArgumentsException,
            WrongCredentialsException,
            AAMException;

    /**
     * @return GUEST token used to access public resources offered in SymbIoTe
     */
    String getGuestToken() throws JWTCreationException, AAMException;

    /**
     * @param loginRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildHomeTokenAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return HOME token used to access restricted resources offered in SymbIoTe
     */
    String getHomeToken(String loginRequest) throws
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException,
            AAMException;

    /**
     * @param remoteHomeToken   that an actor wants to exchange in this AAM for a FOREIGN token
     * @param clientCertificate in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param aamCertificate    in PEM with key matching the IPK claim in the provided token in 'offline' (intranet) scenarios
     * @return FOREIGN token used to access restricted resources offered in SymbIoTe federations
     */
    String getForeignToken(String remoteHomeToken, Optional<String> clientCertificate, Optional<String> aamCertificate) throws
            ValidationException,
            JWTCreationException,
            AAMException;

    /**
     * @return collection of AAMs available in the SymbIoTe ecosystem
     */
    AvailableAAMsCollection getAAMsInternally() throws AAMException;

    /**
     * @return collection of AAMs available in the SymbIoTe ecosystem
     */
    AvailableAAMsCollection getAvailableAAMs() throws AAMException;

    /**
     * @param token                                  that is to be validated
     * @param clientCertificate                      in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param clientCertificateSigningAAMCertificate in PEM being the AAM that signed the clientCertificate  in 'offline' (intranet) scenarios
     * @param foreignTokenIssuingAAMCertificate      in PEM with key matching the IPK claim in the provided FOREIGN token in 'offline' (intranet) scenarios
     * @return validation status
     */
    ValidationStatus validateCredentials(String token,
                                         Optional<String> clientCertificate,
                                         Optional<String> clientCertificateSigningAAMCertificate,
                                         Optional<String> foreignTokenIssuingAAMCertificate) throws AAMException;

    /**
     * @param userManagementRequest related to associated users' management operation.
     * @return Management Status informing about a result of completing requested management operation
     */
    ManagementStatus manageUser(UserManagementRequest userManagementRequest) throws AAMException;

    /**
     * @param credentials of a user whose details should be returned
     * @return details of requested user
     */
    UserDetails getUserDetails(Credentials credentials) throws
            UserManagementException,
            AAMException;
}
