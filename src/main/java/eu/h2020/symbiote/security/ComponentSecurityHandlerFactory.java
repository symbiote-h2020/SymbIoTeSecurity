package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.ComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.SecurityHandler;

/**
 * Builds a component security Handler
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jose Antonio Sanchez Murillo (Atos)
 */
public class ComponentSecurityHandlerFactory {

    private ComponentSecurityHandlerFactory() {
    }

    /**
     * Creates an end-user security handler
     *
     * @param coreAAMAddress                 address to Core AAM
     * @param keystorePath                   where the keystore will be stored
     * @param keystorePassword               needed to access security credentials
     * @param clientId                       name of the component in the form of "componentId@platformId"
     * @param localAAMAddress                needed to acquire the component's authorization credentials
     * @param alwaysUseLocalAAMForValidation when wanting to use local AAM for @{@link SecurityRequest} validation
     * @param componentOwnerUsername         local AAM Admin credentials
     * @param componentOwnerPassword         local AAM Admin credentials
     * @return the component security handler ready to talk with Symbiote components
     * @throws SecurityHandlerException on creation error (e.g. problem with the wallet)
     */
    public static IComponentSecurityHandler getComponentSecurityHandler(String coreAAMAddress,
                                                                        String keystorePath,
                                                                        String keystorePassword,
                                                                        String clientId,
                                                                        String localAAMAddress,
                                                                        boolean alwaysUseLocalAAMForValidation,
                                                                        String componentOwnerUsername,
                                                                        String componentOwnerPassword) throws
            SecurityHandlerException {
        if (clientId.split("@").length != 2) {
            throw new SecurityHandlerException("Component Id has bad form, must be componentId@platformId");
        }
        return new ComponentSecurityHandler(
                new SecurityHandler(keystorePath, keystorePassword, localAAMAddress, componentOwnerUsername, clientId.split("@")[1]),
                localAAMAddress,
                alwaysUseLocalAAMForValidation,
                componentOwnerUsername,
                componentOwnerPassword,
                clientId);
    }
}
