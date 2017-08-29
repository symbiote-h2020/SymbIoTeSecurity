package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.handler.ISecurityHandler;
import eu.h2020.symbiote.security.handler.SecurityHandler;

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
     * @return the security handler ready to talk with Symbiote Security Layer
     * @throws SecurityHandlerException on creation error (e.g. problem with the wallet)
     */
    public static ISecurityHandler getSecurityHandler(String coreAAMAddress,
                                                      String keystorePath,
                                                      String keystorePassword) throws
            SecurityHandlerException {
        return new SecurityHandler(keystorePath, keystorePassword, coreAAMAddress);
    }
}
