package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.certificate.CertificateVerificationException;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;

import java.security.KeyStore;
import java.util.List;
import java.util.Map;

/**
 * Release 2 security handler.
 *
 * @deprecated For release 3 use {@link ISecurityHandler}
 */
@Deprecated
public interface IOldSecurityHandler {

    /**
     * @return list of all currently available security entrypoints to symbiote (login, token (request, validation))
     * for Release 2 with Core certificate, for R3 will include Platforms' certificates
     * @throws SecurityHandlerException on operation error
     */
    List<AAM> getAvailableAAMs() throws SecurityHandlerException;

    /**
     * Request core token using one's Symbiote Core Account
     * <p>
     * TODO R3 rework/add new method so that user can actually request Home Token from any AAM that is his home AAM.
     *
     * @param userName username in Symbiote Core
     * @param password password in Symbiote Core
     * @return Token issued for your user in Symbiote Core
     */
    Token requestCoreToken(String userName, String password);

    /**
     * Requests federated Platform tokens using acquired Core token.
     * TODO R3 review and update to be able to use any kind of symbiote token for requesting federated tokens (pass a
     * token as param).
     *
     * @param aams Symbiote Authentication and Authorization Managers to request federated tokens from
     * @return
     */
    Map<String, Token> requestForeignTokens(List<AAM> aams);

    /**
     * Clears the token wallet (home and core)
     */
    void logout();

    /**
     * @return home token from the local token wallet
     */
    Token getHomeToken();

    /**
     * @return home token from the local token wallet
     */
    Token getCoreToken();

    /**
     * Validates the certificate used by the user in challenge-response operations against the exposed Core AAM root
     * CA certificate
     *
     * @param p12Certificate the local certificate store (either issued by Platform or Core AAM)
     * @return true if valid
     * @throws CertificateVerificationException on validation error
     */
    boolean certificateValidation(KeyStore p12Certificate) throws CertificateVerificationException;

    /**
     * @param token to be validated
     * @return validation status of the core token
     */
    ValidationStatus verifyCoreToken(Token token);

    /**
     * Validates the given token against the exposed relevant AAM certificate
     * <p>
     *
     * @param aam   Platform AAM which issued the token
     * @param token to be validated
     * @return validation status of the core token
     */
    ValidationStatus verifyPlatformToken(AAM aam, Token token);
}
