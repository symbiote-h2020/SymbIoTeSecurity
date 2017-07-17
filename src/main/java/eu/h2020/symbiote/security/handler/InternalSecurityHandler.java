package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.clients.amqp.LocalAAMOverAMQPClient;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.helpers.TokenHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Internal Security Handler to be used by Symbiote Components, includes AMQP communication with local AAMs
 *
 * @author Elena Garrido (Atos)
 * @author Mikołaj Dobski (PSNC)
 * @version 08/03/2017
 *          ! \class SecurityHandler
 *          \brief This class implement the methods to be used by the component in order to integrate with the
 *          security from symbIoTe
 * @deprecated use @{@link ISecurityHandler} starting release 3 of SymbIoTe
 **/
@Deprecated
public class InternalSecurityHandler extends SecurityHandler {
    private static Log log = LogFactory.getLog(InternalSecurityHandler.class);
    private LocalAAMOverAMQPClient platformMessageHandler = null;

    /**
     * Initializes the Security Handler for symbiote components
     *
     * @param symbioteCoreInterfaceAddress used to access exposed Core AAM services
     * @param rabbitMQHostIP               used to access platform AAM over AMQP
     * @param rabbitMQUsername             used to access platform AAM over AMQP
     * @param rabbitMQPassword             used to access platform AAM over AMQP
     */
    public InternalSecurityHandler(String symbioteCoreInterfaceAddress, String rabbitMQHostIP, String
            rabbitMQUsername, String
                                           rabbitMQPassword) {
        super(symbioteCoreInterfaceAddress);
        this.platformMessageHandler = new LocalAAMOverAMQPClient(rabbitMQHostIP, rabbitMQUsername,
                rabbitMQPassword);
        this.tokenHandler = new TokenHelper(this.coreMessageHandler, platformMessageHandler);
    }

    /**
     * Request token from your local/home AAM over AMQP
     * <p>
     *
     * @param userName username in local AAM
     * @param password password in local AAM
     * @return Token issued for your user in local AAM
     */
    public Token requestHomeToken(String userName, String password) throws SecurityHandlerException {
        Token homeToken = sessionInformation.getHomeToken();
        if (homeToken == null) {
            //not logged in
            Credentials credentials = new Credentials();
            credentials.setUsername(userName);
            credentials.setPassword(password);
            homeToken = platformMessageHandler.login(credentials);
            sessionInformation.setHomeToken(homeToken);
            if (sessionInformation.getHomeToken() == null) {
                log.error(SecurityConstants.ERR_WRONG_CREDENTIALS);
                throw new SecurityException(SecurityConstants.ERR_WRONG_CREDENTIALS);
            }
        }
        return homeToken;
    }

    /**
     * Request federated core token using your home platform token
     *
     * @param userName home platform username
     * @param password home platform password
     * @return Token issued according to you Home Platform and Core Federation
     * @apiNote JUST FOR INTERNAL PLATFORM USAGE
     */
    public Token requestFederatedCoreToken(String userName, String password) throws SecurityHandlerException {
        if (platformMessageHandler == null) {
            throw new SecurityHandlerException("Security Handler wasn't configured to access Platform AAM over AMQP, " +
                    "use the 4 parameters constructor for that");
        }
        Token coreToken = sessionInformation.getCoreToken();
        if (coreToken == null) {
            //not logged in
            Credentials credentials = new Credentials();
            credentials.setUsername(userName);
            credentials.setPassword(password);
            Token homeToken = platformMessageHandler.login(credentials);
            //TODO challenge response procedure??
            coreToken = tokenHandler.requestFederatedCoreToken(homeToken);
            sessionInformation.setHomeToken(homeToken);
            sessionInformation.setCoreToken(coreToken);
            if (sessionInformation.getHomeToken() == null) {
                log.error(SecurityConstants.ERR_WRONG_CREDENTIALS);
                throw new SecurityException(SecurityConstants.ERR_WRONG_CREDENTIALS);
            }

        }

        ValidationStatus validationStatus = tokenHandler.validateCoreToken(coreToken);
        if (validationStatus != ValidationStatus.VALID)
            throw new SecurityException("Received core token is not valid");
        return coreToken;
    }


    /**
     * Validates the given token against the exposed relevant AAM certificate
     * <p>
     *
     * @param token to be validated
     * @return validation status of the core token
     */
    public ValidationStatus verifyHomeToken(Token token) {
        return tokenHandler.validateHomeToken(token);
    }
}