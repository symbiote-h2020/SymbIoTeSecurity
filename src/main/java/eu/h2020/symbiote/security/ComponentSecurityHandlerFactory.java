package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.ComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.DummySecurityHandler;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;

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
     * @param coreAAMAddress                 Symbiote Core AAM address which is available on the symbiote security webpage
     * @param keystorePassword               needed to access security credentials
     * @param clientId                       name of the component in the form of "componentId@platformId"
     * @param isOnline                       TODO @JASM...  not really sure what it does
     * @param localAAMAddress                when using only local AAM for @{@link SecurityRequest} validation
     * @param alwaysUseLocalAAMForValidation when wanting to use local AAM for @{@link SecurityRequest} validation
     * @param componentOwnerUsername         AAMAdmin credentials for core components and platform owner credentials for platform components
     * @param componentOwnerPassword         AAMAdmin credentials for core components and platform owner credentials for platform components
     * @return the component security handler ready to talk with Symbiote components
     * @throws SecurityHandlerException on creation error (e.g. problem with the wallet)
     */
    public static IComponentSecurityHandler getComponentSecurityHandler(String coreAAMAddress,
                                                                        String keystorePassword,
                                                                        String clientId,
                                                                        boolean isOnline,
                                                                        String localAAMAddress,
                                                                        boolean alwaysUseLocalAAMForValidation,
                                                                        String componentOwnerUsername,
                                                                        String componentOwnerPassword) throws
            SecurityHandlerException {
        // TODO @JASM replace dummy with proper security handler
        return new ComponentSecurityHandler(
                new DummySecurityHandler(coreAAMAddress, keystorePassword, clientId, isOnline),
                localAAMAddress,
                alwaysUseLocalAAMForValidation,
                componentOwnerUsername,
                componentOwnerPassword,
                clientId);
    }
}
