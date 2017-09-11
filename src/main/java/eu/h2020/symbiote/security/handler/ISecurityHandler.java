package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.AAM;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Security Handler interface proposed for Release 3 of SymbIoTe.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Pietro Tedeschi (CNIT)
 */
public interface ISecurityHandler {

    /**
     * @return map of all currently available security entrypoints to symbiote (getCertificate, login, token
     * validation) as obtained by the core AAM
     * @throws SecurityHandlerException on operation error
     */
    Map<String, AAM> getAvailableAAMs() throws SecurityHandlerException;

    /**
     * @param aam the aam to retrieve the map from, note the symbIoTe Core AAM has always the up-to-date information
     * @return map of all currently available security entrypoints to symbiote (getCertificate, login, token
     * validation)
     * @throws SecurityHandlerException on operation error
     */
    Map<String, AAM> getAvailableAAMs(AAM aam) throws SecurityHandlerException;

    /**
     * Retrieves your home token from the given AAM you have account in.
     *
     * @param aam AAM instance to get a home token from
     * @return home token
     * @throws SecurityHandlerException on operation error
     */
    Token login(AAM aam) throws SecurityHandlerException, ValidationException;

    /**
     * Login to foreign AAMs (you don't have account in) using home token.
     *
     * @param foreignAAMs to get the Tokens from
     * @param homeToken   used to acquire foreign tokens
     * @return map of the foreign tokens that were acquired using a given home token
     * @throws SecurityHandlerException on operation error
     */
    Map<AAM, Token> login(List<AAM> foreignAAMs, String homeToken)
            throws SecurityHandlerException;

    /**
     * @param aam Authentication and Authorization Manager to request guest token from
     * @return guest token that allows access to all public resources in symbIoTe
     */
    Token loginAsGuest(AAM aam) throws ValidationException, SecurityHandlerException;

    /**
     * Removes all the acquired tokens from memory
     */
    void clearCachedTokens();

    /**
     * Used to acquire a certificate(PKI) for this client from the home AAM
     * This private key will be used to sign-off the request to AAM
     *
     * @param homeAAM  the Authenticantion and Authorization Manager the user has account in
     * @param username of the user in the home AAM
     * @param password of the user in the home AAM
     * @param clientId that will be bound with the user and this client
     * @return certificate used by this client for challenge-response operations
     * @throws SecurityHandlerException on operation error
     */
    Certificate getCertificate(AAM homeAAM,
                               String username,
                               String password,
                               String clientId)
            throws SecurityHandlerException;

    /**
     * Used to validate a Token to the AAM
     *
     * @param validationAuthority where the token should be validated (ideally it should be the token issuer authority)
     * @param token               to be validated
     * @return validation status of the given token
     */
    ValidationStatus validate(AAM validationAuthority, String token,
                              Optional<String> clientCertificate,
                              Optional<String> clientCertificateSigningAAMCertificate,
                              Optional<String> foreignTokenIssuingAAMCertificate);

    Map<String, BoundCredentials> getAcquiredCredentials();

    /**
     * @param componentIdentifier component identifier or {@link SecurityConstants#AAM_COMPONENT_NAME} for AAM CA certificate
     * @param platformIdentifier  for a platform component or {@link SecurityConstants#CORE_AAM_INSTANCE_ID} for Symbiote core components
     */
    Certificate getComponentCertificate(String componentIdentifier, String platformIdentifier);

    AAM getCoreAAMInstance();
}
