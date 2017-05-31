package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.certificate.CertificateValidator;
import eu.h2020.symbiote.security.certificate.CertificateVerificationException;
import eu.h2020.symbiote.security.certificate.ECDSAHelper;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.rest.clients.CoreAAMClient;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.session.SessionInformation;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.TokenHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.KeyStore;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class exposing the library from security handler
 *
 * @author Elena Garrido (Atos)
 * @author Mikołaj Dobski (PSNC)
 * @version 08/03/2017
 *          ! \class SecurityHandler
 *          \brief This class implement the methods to be used by the component in order to integrate with the
 *          security from symbIoTe
 *          @deprecated use @{@link ISecurityHandler} starting release 3 of SymbIoTe
 **/
@Deprecated
public class SecurityHandler implements IOldSecurityHandler {
    private static Log log = LogFactory.getLog(SecurityHandler.class);
    protected SessionInformation sessionInformation = null;
    protected TokenHandler tokenHandler = null;
    protected CoreAAMClient coreMessageHandler = null;
    private CertificateValidator certificateValidator = null;

    /**
     * Initializes the Security Handler for 3rd Party applications
     *
     * @param symbioteCoreInterfaceAddress used to access exposed Core AAM services
     */
    public SecurityHandler(String symbioteCoreInterfaceAddress) {
        ECDSAHelper.enableECDSAProvider();
        this.coreMessageHandler = new CoreAAMClient(symbioteCoreInterfaceAddress);
        this.sessionInformation = new SessionInformation();
        this.tokenHandler = new TokenHandler(this.coreMessageHandler, null);
        this.certificateValidator = new CertificateValidator(this.coreMessageHandler);
    }

    /**
     * @return list of all currently available security entrypoints to symbiote (login, token (request, validation))
     * for Release 2 with Core certificate, for R3 will include Platforms' certificates
     * @throws SecurityHandlerException on operation error
     */
    @Override
    public List<AAM> getAvailableAAMs() throws SecurityHandlerException {
        // TODO integrate with SessionInformation
        return coreMessageHandler.getAvailableAAMs();
    }

    /**
     * Request core token using one's Symbiote Core Account
     * <p>
     * TODO R3 rework/add new method so that user can actually request Home Token from any AAM that is his home AAM.
     *
     * @param userName username in Symbiote Core
     * @param password password in Symbiote Core
     * @return Token issued for your user in Symbiote Core
     */
    @Override
    public Token requestCoreToken(String userName, String password) {
        Token coreToken = sessionInformation.getCoreToken();
        if (coreToken == null) {
            //not logged in
            Credentials credentials = new Credentials();
            credentials.setUsername(userName);
            credentials.setPassword(password);
            coreToken = coreMessageHandler.login(credentials);
            sessionInformation.setCoreToken(coreToken);
            if (sessionInformation.getCoreToken() == null) {
                log.error(AAMConstants.ERR_WRONG_CREDENTIALS);
                throw new SecurityException(AAMConstants.ERR_WRONG_CREDENTIALS);
            }
        }
        return coreToken;
    }

    /**
     * Requests federated Platform tokens using acquired Core token.
     * TODO R3 review and update to be able to use any kind of symbiote token for requesting federated tokens (pass a token as param).
     *
     * @param aams Symbiote Authentication and Authorization Managers to request federated tokens from
     * @return
     */
    @Override
    public Map<String, Token> requestForeignTokens(List<AAM> aams) {
        HashMap<String, Token> federatedTokens = null;

        Token requestToken = sessionInformation.getCoreToken();
        if (requestToken != null) {
            //logged in
            federatedTokens = new HashMap<>();
            for (AAM aam : aams) {
                // the user should not request a federated token if he has a home token in that aam
                if (aam.getAamInstanceId().equals(requestToken.getClaims().getIssuer()))
                    continue;
                // request federated token from that the foreign AAM
                Token federatedToken = sessionInformation.getForeignToken(aam.getAamInstanceId());
                if (federatedToken == null) {
                    federatedToken = tokenHandler.requestFederatedToken(aam, requestToken);
                    sessionInformation.setForeignToken(aam.getAamInstanceId(), federatedToken);
                }
                federatedTokens.put(aam.getAamInstanceId(), federatedToken);
            }
        }
        return federatedTokens;
    }

    /**
     * Clears the token wallet (home and core)
     */
    @Override
    public void logout() {
        sessionInformation.setHomeToken(null);
        sessionInformation.setCoreToken(null);
    }

    /**
     * @return home token from the local token wallet
     */
    @Override
    public Token getHomeToken() {
        return sessionInformation.getHomeToken();
    }

    /**
     * @return core token from the local token wallet
     */
    @Override
    public Token getCoreToken() {
        return sessionInformation.getCoreToken();
    }

    /**
     * Validates the certificate used by the user in challenge-response operations against the exposed Core AAM root
     * CA certificate
     *
     * @param p12Certificate the local certificate store (either issued by Platform or Core AAM)
     * @return true if valid
     * @throws CertificateVerificationException on validation error
     */
    @Override
    public boolean certificateValidation(KeyStore p12Certificate) throws CertificateVerificationException {
        return certificateValidator.validate(p12Certificate);
    }

    /**
     * @param token to be validated
     * @return validation status of the core token
     */
    @Override
    public ValidationStatus verifyCoreToken(Token token) {
        return tokenHandler.validateCoreToken(token);
    }

    /**
     * Validates the given token against the exposed relevant AAM certificate
     * <p>
     *
     * @param aam   Platform AAM which issued the token
     * @param token to be validated
     * @return validation status of the core token
     */
    @Override
    public ValidationStatus verifyPlatformToken(AAM aam, Token token) {
        return tokenHandler.validateForeignPlatformToken(aam, token);
    }
}
