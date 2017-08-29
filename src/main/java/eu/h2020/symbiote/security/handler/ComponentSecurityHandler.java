package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.SecurityCredentials;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.helpers.ABACPolicyHelper;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * used by SymbIoTe Components to integrate with the security layer
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Jose Antonio Sanchez Murillo (Atos)
 */
public class ComponentSecurityHandler implements IComponentSecurityHandler {
    private final ISecurityHandler securityHandler;
    private final AAM localAAM;
    private final boolean alwaysUseLocalAAMForValidation;
    private final String componentOwnerUsername;
    private final String componentOwnerPassword;
    private final String combinedClientIdentifier;
    private final String componentId;
    private final String platformId;

    public ComponentSecurityHandler(ISecurityHandler securityHandler,
                                    String localAAMAddress,
                                    boolean alwaysUseLocalAAMForValidation,
                                    String componentOwnerUsername,
                                    String componentOwnerPassword,
                                    String componentId) throws SecurityHandlerException {
        this.securityHandler = securityHandler;
        this.localAAM = new AAM(localAAMAddress, "", "", new Certificate(), new HashMap<>());
        this.alwaysUseLocalAAMForValidation = alwaysUseLocalAAMForValidation;
        this.componentOwnerUsername = componentOwnerUsername;
        this.componentOwnerPassword = componentOwnerPassword;
        String[] splitComponentId = componentId.split("@");
        if (splitComponentId.length != 2)
            throw new SecurityHandlerException("Component Id has bad form, must be componentId@platformId");
        this.componentId = splitComponentId[0];
        this.platformId = splitComponentId[1];
        this.combinedClientIdentifier = componentId;
    }

    @Override
    public ValidationStatus isReceivedSecurityRequestValid(SecurityRequest securityRequest) throws
            SecurityHandlerException {

        // verifying that the request is integral and the client should posses the tokens in it
        try {
            if (!MutualAuthenticationHelper.isSecurityRequestVerified(securityRequest))
                return ValidationStatus.INVALID_TRUST_CHAIN;
        } catch (NoSuchAlgorithmException | MalformedJWTException | InvalidKeySpecException | ValidationException e) {
            e.printStackTrace();
            throw new SecurityHandlerException(e.getMessage());
        }

        Map<String, AAM> availableAAMs = new HashMap<>();
        if (!alwaysUseLocalAAMForValidation)
            availableAAMs = securityHandler.getAvailableAAMs(localAAM); // retrieving AAMs available to use them for validation

        // validating the authorization tokens
        for (SecurityCredentials securityCredentials : securityRequest.getSecurityCredentials()) {
            try {
                Token authorizationToken = new Token(securityCredentials.getToken());
                AAM validationAAM;
                // set proper validation AAM
                if (alwaysUseLocalAAMForValidation) {
                    validationAAM = localAAM;
                } else {
                    // try to resolve the issuing AAM
                    validationAAM = availableAAMs.get(authorizationToken.getClaims().getIssuer());
                    if (validationAAM == null)// fallback to local AAM
                        validationAAM = localAAM;
                }

                // validate
                ValidationStatus tokenValidationStatus = securityHandler.validate(
                        validationAAM,
                        authorizationToken.getToken(),
                        Optional.of(securityCredentials.getClientCertificate()),
                        Optional.of(securityCredentials.getClientCertificateSigningAAMCertificate()),
                        Optional.of(securityCredentials.getForeignTokenIssuingAAMCertificate()));
                // any invalid token causes the whole validation to fail
                if (tokenValidationStatus != ValidationStatus.VALID)
                    return tokenValidationStatus;
            } catch (ValidationException e) {
                e.printStackTrace();
                throw new SecurityHandlerException(e.getMessage());
            }
        }

        // all security checks passed
        return ValidationStatus.VALID;
    }

    @Override
    public boolean isReceivedServiceResponseVerified(String serviceResponse,
                                                     Certificate serviceCertificate) throws SecurityHandlerException {
        try {
            return MutualAuthenticationHelper.isServiceResponseVerified(serviceResponse, serviceCertificate);
        } catch (NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
            throw new SecurityHandlerException("Failed to verify the serviceResponse, the operation should be retried: " + e.getMessage());
        }
    }


    @Override
    public Set<String> getAuthorizedResourcesIdentifiers(String deploymentId, Map<String, IAccessPolicy> accessPolicies,
                                                         SecurityRequest securityRequest) throws SecurityHandlerException {
        //TODO Mikolaj - do your magic
        return ABACPolicyHelper.checkRequestedOperationAccess(deploymentId, accessPolicies, securityRequest).getAvailableResources();
    }

    @Override
    public SecurityRequest generateSecurityRequestUsingCoreCredentials() throws
            SecurityHandlerException {
        Set<AuthorizationCredentials> authorizationCredentials = new HashSet<>();
        HomeCredentials coreCredentials = getCoreAAMCredentials().homeCredentials;

        authorizationCredentials.add(new AuthorizationCredentials(coreCredentials.homeToken, coreCredentials.homeAAM, coreCredentials));
        try {
            return MutualAuthenticationHelper.getSecurityRequest(authorizationCredentials, false);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new SecurityHandlerException("Failed to generate security request: " + e.getMessage());
        }
    }

    @Override
    public String generateServiceResponse() throws SecurityHandlerException {
        BoundCredentials coreAAMBoundCredentials = getCoreAAMCredentials();
        try {
            // generating the service response
            return MutualAuthenticationHelper.getServiceResponse(coreAAMBoundCredentials.homeCredentials.privateKey, new Date().getTime());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new SecurityHandlerException("Failed to generate service response");
        }
    }

    @Override
    public ISecurityHandler getSecurityHandler() {
        return securityHandler;
    }

    /**
     * gets the credentials from the wallet, if missing then issues them and adds to the wallet
     *
     * @return required for authorizing operations in the symbiote Core
     * @throws SecurityHandlerException on error
     */
    private BoundCredentials getCoreAAMCredentials() throws SecurityHandlerException {
        
        
        AAM coreAAM = securityHandler.getAvailableAAMs(localAAM).get(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID);
        if (coreAAM == null)
            throw new SecurityHandlerException("Core AAM unavailable");
        BoundCredentials coreAAMBoundCredentials = securityHandler.getAcquiredCredentials().get(coreAAM);
        if (coreAAMBoundCredentials == null) {
            Certificate componentCertificate = componentCertificate = securityHandler.getCertificate(
                coreAAM,
                componentOwnerUsername,
                componentOwnerPassword,
                combinedClientIdentifier);
            coreAAMBoundCredentials = securityHandler.getAcquiredCredentials().get(coreAAM.getAamInstanceId());
        }

        // check that we have a valid token
        boolean isCoreTokenRefreshNeeded = false;
        try {
            if (coreAAMBoundCredentials.homeCredentials.homeToken == null
                    || JWTEngine.validateTokenString(coreAAMBoundCredentials.homeCredentials.homeToken.getToken()) != ValidationStatus.VALID) {
                isCoreTokenRefreshNeeded = true;
            }
        } catch (ValidationException e) {
            isCoreTokenRefreshNeeded = true;
        }

        // fetching the core token using the security handler
        if (isCoreTokenRefreshNeeded) {
            // gets the token and puts it in the wallet
            try {
                securityHandler.login(coreAAM);
                // fetching updated token from the wallet
                coreAAMBoundCredentials = securityHandler.getAcquiredCredentials().get(coreAAM);
                
            } catch (ValidationException e) {
                throw new SecurityHandlerException("Can't refesh token", e);
            }
            
        }
        return coreAAMBoundCredentials;
    }
}
