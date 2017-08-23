package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.handler.DummySecurityHandler;
import eu.h2020.symbiote.security.handler.ISecurityHandler;

/**
 * Builds an end user SecurityHandler
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jose Antonio Sanchez Murillo (Atos)
 */
public class ClientSecurityHandlerFactory {

    private ClientSecurityHandlerFactory() {
    }

    /**
     * Creates an end-user security handler
     *
     * @param coreAAMAddress   Symbiote Core AAM address which is available on the symbiote security webpage
     * @param keystorePassword needed to access security credentials
     * @param clientId         identifier of this app/device/client, must not contain "@"
     * @param isOnline         TODO @JASM... not really sure what it does
     * @return the security handler ready to talk with Symbiote Security Layer
     * @throws SecurityHandlerException on creation error (e.g. problem with the wallet)
     */
    public static ISecurityHandler getSecurityHandler(String coreAAMAddress,
                                                      String keystorePassword,
                                                      String clientId,
                                                      boolean isOnline) throws
            SecurityHandlerException {
        // TODO @JASM replace with proper constructor
        return new DummySecurityHandler(coreAAMAddress, keystorePassword, clientId, isOnline);
    }
}
