package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.ComponentIdentifiers;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.handler.ComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.SecurityHandler;
import eu.h2020.symbiote.security.helpers.CryptoHelper;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Map;
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
     * @param clientId                       name of the component in the form of "componentId@platformId", componentId should be consistent with {@link ComponentIdentifiers}
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
        return getComponentSecurityHandler(
                keystorePath,
                keystorePassword,
                clientId,
                localAAMAddress,
                componentOwnerUsername,
                componentOwnerPassword,
                Optional.of(new NullAnomalyListenerSecurity()));
    }

    /**
     * Creates a component security handler
     *
     * @param keystorePath           where the keystore will be stored
     * @param keystorePassword       needed to access security credentials
     * @param clientId               name of the component in the form of "componentId@platformId", componentId should be consistent with {@link ComponentIdentifiers}
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
        String platformId = clientId.split("@")[1];
        SecurityHandler securityHandler = new SecurityHandler(keystorePath, keystorePassword, localAAMAddress, platformId);
        if (securityHandler.getAcquiredCredentials().containsKey(platformId)) {
            Map<String, AAM> availableAAMs = securityHandler.getAvailableAAMs(localAAMAddress);
            Certificate componentCertificate = securityHandler.getAcquiredCredentials().get(platformId).homeCredentials.certificate;
            try {
                if (!CryptoHelper.isClientCertificateChainTrusted(availableAAMs.get(SecurityConstants.CORE_AAM_INSTANCE_ID).getAamCACertificate().getCertificateString(),
                        availableAAMs.get(platformId).getAamCACertificate().getCertificateString(),
                        componentCertificate.getCertificateString())) {
                    throw new SecurityHandlerException(SecurityHandlerException.AAM_CERTIFICATE_DIFFERENT_THAN_IN_KEYSTORE);
                }
            } catch (NoSuchAlgorithmException | CertificateException | NoSuchProviderException | IOException e) {
                throw new SecurityHandlerException("Error during checking the certificate trust chain occured");
            }
        }

        return new ComponentSecurityHandler(
                securityHandler,
                localAAMAddress,
                componentOwnerUsername,
                componentOwnerPassword,
                clientId,
                anomalyListenerSecurity);
    }
}
