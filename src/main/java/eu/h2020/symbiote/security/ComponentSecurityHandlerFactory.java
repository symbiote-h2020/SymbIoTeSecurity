package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.handler.*;

import java.util.Optional;

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
     * Creates an component security handler
     *
     * @param coreAAMAddress                 address to Core AAM (no longer used, add proper address in localAAMAddress parameter)
     * @param keystorePath                   where the keystore will be stored
     * @param keystorePassword               needed to access security credentials
     * @param clientId                       name of the component in the form of "componentId@platformId"
     * @param localAAMAddress                needed to acquire the component's authorization credentials
     * @param alwaysUseLocalAAMForValidation forced true due to usage of caching tools
     * @param componentOwnerUsername         local AAM Admin credentials
     * @param componentOwnerPassword         local AAM Admin credentials
     * @return the component security handler ready to talk with Symbiote components
     * @throws SecurityHandlerException on creation error (e.g. problem with the wallet)
     *
     * @deprecated use {@link #getComponentSecurityHandler(String, String, String, String, String, String, Optional)}
     */
    @Deprecated
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
                new SecurityHandler(keystorePath, keystorePassword, localAAMAddress, clientId.split("@")[1]),
                localAAMAddress,
                componentOwnerUsername,
                componentOwnerPassword,
                clientId,
                Optional.of(new NullAnomalyListenerSecurity()));
    }

    /**
     * Creates a component security handler
     *
     * @param keystorePath           where the keystore will be stored
     * @param keystorePassword       needed to access security credentials
     * @param clientId               name of the component in the form of "componentId@platformId"
     * @param localAAMAddress        needed to acquire the component's authorization credentials
     * @param componentOwnerUsername local AAM Admin credentials
     * @param componentOwnerPassword local AAM Admin credentials
     * @return the component security handler ready to talk with Symbiote components
     * @throws SecurityHandlerException on creation error (e.g. problem with the wallet)
     */
    public static IComponentSecurityHandler getComponentSecurityHandler(String keystorePath,
                                                                        String keystorePassword,
                                                                        String clientId,
                                                                        String localAAMAddress,
                                                                        String componentOwnerUsername,
                                                                        String componentOwnerPassword,
                                                                        Optional<IAnomalyListenerSecurity> anomalyListenerSecurity) throws
            SecurityHandlerException {
        if (clientId.split("@").length != 2) {
            throw new SecurityHandlerException("Component Id has bad form, must be componentId@platformId");
        }
        return new ComponentSecurityHandler(
                new SecurityHandler(keystorePath, keystorePassword, localAAMAddress, clientId.split("@")[1]),
                localAAMAddress,
                componentOwnerUsername,
                componentOwnerPassword,
                clientId,
                anomalyListenerSecurity);
    }
}
