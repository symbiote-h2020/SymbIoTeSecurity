package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.AAM;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * End user Security Handler interface proposed for Release 3 of SymbIoTe.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Pietro Tedeschi (CNIT)
 * @author Jose Antonio Sanchez Murillo (Atos)
 */
public interface ISecurityHandler {

    /**
     * @return map of all currently available security entrypoints to symbiote (getCertificate, login, token
     * validation)
     * @throws SecurityHandlerException on operation error
     */
    Map<String, AAM> getAvailableAAMs() throws SecurityHandlerException;

    /**
     * @return map of all credentials available to use in authentication and authorization operations
     * @throws SecurityHandlerException on error
     */
    Map<AAM, BoundCredentials> getAcquiredCredentials() throws SecurityHandlerException;

    /**
     * Retrieves your home token from the given AAM you have account in.
     *
     * @param homeCredentials used to build loginRequest
     * @return home token
     * @throws SecurityHandlerException on operation error
     */
    Token login(HomeCredentials homeCredentials) throws SecurityHandlerException;

    /**
     * Login to foreign AAMs (you don't have account in) using home token.
     *
     * @param foreignAAMs     to get the Tokens from
     * @param homeCredentials used to aquire foreignToken
     * @return map of the foreign tokens that were acquired using a given home token
     * @throws SecurityHandlerException on operation error
     */
    Map<AAM, Token> login(List<AAM> foreignAAMs, HomeCredentials homeCredentials)
            throws SecurityHandlerException;

    /**
     * @param aam Authentication and Authorization Manager to request guest token from
     * @return guest token that allows access to all public resources in symbIoTe
     */
    Token loginAsGuest(AAM aam);

    /**
     * Removes all the acquired tokens from memory
     */
    void clearCachedTokens();

    /**
     * Used to acquire a certificate for this client from the home AAM
     *
     * @param homeAAM   the Authenticantion and Authorization Manager the user has account in
     * @param username  of the user in the home AAM
     * @param password  of the user in the home AAM
     * @param clientId  that will be bound with the user and this client
     * @param clientCSR Certificate Signing Request required to issue a certificate for this client, it should be
     *                  PKCS10CertificationRequest in PEM format
     * @return certificate used by this client for challenge-response operations
     * @throws SecurityHandlerException on operation error
     */
    Certificate getCertificate(AAM homeAAM,
                               String username,
                               String password,
                               String clientId,
                               String clientCSR)
            throws SecurityHandlerException;

    /**
     * @param validationAuthority                    where the token should be validated (ideally it should be the token issuer authority)
     * @param token                                  that is to be validated
     * @param clientCertificate                      in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param clientCertificateSigningAAMCertificate in PEM being the AAM that signed the clientCertificate  in 'offline' (intranet) scenarios
     * @param foreignTokenIssuingAAMCertificate      in PEM with key matching the IPK claim in the provided FOREIGN token in 'offline' (intranet) scenarios
     * @return validation status of the given token
     */
    ValidationStatus validate(AAM validationAuthority,
                              String token,
                              Optional<String> clientCertificate,
                              Optional<String> clientCertificateSigningAAMCertificate,
                              Optional<String> foreignTokenIssuingAAMCertificate);
}
