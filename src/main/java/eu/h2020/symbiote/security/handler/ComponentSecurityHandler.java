package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.clients.SymbioteComponentClientFactory;
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
import eu.h2020.symbiote.security.communication.interfaces.IFeignADMComponentClient;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.helpers.ABACPolicyHelper;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;
import feign.FeignException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

/**
 * used by SymbIoTe Components to integrate with the security layer
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Jose Antonio Sanchez Murillo (Atos)
 */
public class ComponentSecurityHandler implements IComponentSecurityHandler {

    private static final Log log = LogFactory.getLog(ComponentSecurityHandler.class);
    private final ISecurityHandler securityHandler;
    private final AAM localAAM;
    private final String componentOwnerUsername;
    private final String componentOwnerPassword;
    private final String combinedClientIdentifier;
    private IFeignADMComponentClient admComponentClient;

    public ComponentSecurityHandler(ISecurityHandler securityHandler,
                                    String localAAMAddress,
                                    String componentOwnerUsername,
                                    String componentOwnerPassword,
                                    String componentId) throws SecurityHandlerException {
        this.securityHandler = securityHandler;
        if (componentOwnerUsername.isEmpty()
                || !componentOwnerUsername.matches("^(([\\w-])+)$")
                || componentOwnerPassword.isEmpty())
            throw new SecurityHandlerException("Bad credentials");
        this.componentOwnerUsername = componentOwnerUsername;
        this.componentOwnerPassword = componentOwnerPassword;
        String[] splitComponentId = componentId.split("@");
        if (splitComponentId.length != 2
                || !componentId.matches("^(([\\w-])+)(@)(([\\w-])+)$"))
            throw new SecurityHandlerException("Component Id has bad form, must be componentId@platformId");
        this.combinedClientIdentifier = componentId;
        this.localAAM = securityHandler.getAvailableAAMs(localAAMAddress).get(splitComponentId[1]);
        if (this.localAAM == null) {
            throw new SecurityHandlerException("You are not connected to your local aam");
        }

        // checks if the provided AAM credentials are valid
        generateServiceResponse();
    }


    private ValidationStatus isReceivedSecurityRequestValid(SecurityRequest securityRequest) throws
            SecurityHandlerException {

        // verifying that the request is integral and the client should posses the tokens in it
        try {
            if (!MutualAuthenticationHelper.isSecurityRequestVerified(securityRequest)) {
                log.debug("The security request failed mutual authentication check");
                return ValidationStatus.INVALID_TRUST_CHAIN;
            }
        } catch (NoSuchAlgorithmException | MalformedJWTException | InvalidKeySpecException | ValidationException e) {
            log.error(e);
            throw new SecurityHandlerException(e.getMessage());
        }

        // validating the authorization tokens
        for (SecurityCredentials securityCredentials : securityRequest.getSecurityCredentials()) {
            try {
                Token authorizationToken = new Token(securityCredentials.getToken());
                ValidationStatus tokenValidationStatus;
                AAM issuer = securityHandler.getAvailableAAMs(localAAM).get(authorizationToken.getClaims().getIssuer());
                if (issuer == null
                        || issuer.getAamCACertificate().getCertificateString().isEmpty()) {
                    throw new SecurityHandlerException("ISSUER platform certificate is not available");
                }
                tokenValidationStatus = JWTEngine.validateTokenString(authorizationToken.toString(), issuer.getAamCACertificate().getX509().getPublicKey());
                if (tokenValidationStatus != ValidationStatus.VALID)
                    return tokenValidationStatus;

                // validate
                tokenValidationStatus = securityHandler.validate(
                        localAAM,
                        authorizationToken.getToken(),
                        Optional.of(securityCredentials.getClientCertificate()),
                        Optional.of(securityCredentials.getClientCertificateSigningAAMCertificate()),
                        Optional.of(securityCredentials.getForeignTokenIssuingAAMCertificate()));
                // any invalid token causes the whole validation to fail
                if (tokenValidationStatus != ValidationStatus.VALID) {
                    log.debug("token was invalidated with the following reason: " + tokenValidationStatus);
                    return tokenValidationStatus;
                }
            } catch (ValidationException | CertificateException e) {
                log.error(e);
                throw new SecurityHandlerException(e.getMessage());
            }
        }

        // all security checks passed
        return ValidationStatus.VALID;
    }

    @Override
    public boolean isReceivedServiceResponseVerified(String serviceResponse,
                                                     String componentIdentifier,
                                                     String platformIdentifier)
            throws SecurityHandlerException {
        try {
            return MutualAuthenticationHelper.isServiceResponseVerified(serviceResponse,
                    securityHandler.getComponentCertificate(componentIdentifier, platformIdentifier));
        } catch (NoSuchAlgorithmException | CertificateException e) {
            log.error("Failed to verify the serviceResponse, the operation should be retried: " + e.getMessage());
            return false;
        }
    }


    @Override
    public Set<String> getSatisfiedPoliciesIdentifiers(Map<String, IAccessPolicy> accessPolicies,
                                                       SecurityRequest securityRequest) {
        return getSatisfiedPoliciesIdentifiers(accessPolicies, securityRequest, new HashMap<>());
    }

    @Override
    public Set<String> getSatisfiedPoliciesIdentifiers(Map<String, IAccessPolicy> accessPolicies,
                                                       SecurityRequest securityRequest,
                                                       Map<SecurityCredentials, ValidationStatus> alreadyValidatedCredentialsCache) {

        Set<String> accessiblePolicies = new HashSet<>();
        // resolving which tokens authorize access to resources -> filtering the security request to only contain business request relevant credentials
        Map<String, Set<SecurityCredentials>> abacResolverResponse = ABACPolicyHelper.checkRequestedOperationAccess(accessPolicies, securityRequest);

        // validating credentials for each resource
        for (Map.Entry<String, Set<SecurityCredentials>> authorizedPolicy : abacResolverResponse.entrySet()) {
            int neededCredentials = authorizedPolicy.getValue().size();
            int validatedCredentials = 0;

            // validating each credentials
            for (SecurityCredentials partialPolicyCredentials : authorizedPolicy.getValue()) {
                // trying to retrieve the policy from our cache
                ValidationStatus validationStatus = alreadyValidatedCredentialsCache.get(partialPolicyCredentials);
                // policy already checked
                if (validationStatus != null) {
                    // and valid
                    if (validationStatus == ValidationStatus.VALID)
                        validatedCredentials++;
                    continue;
                }

                // need to validate the partial policy
                Set<SecurityCredentials> credentialsForVerification = new HashSet<>(1);
                credentialsForVerification.add(partialPolicyCredentials);
                try {
                    // validating the current policy
                    ValidationStatus freshValidationStatus = isReceivedSecurityRequestValid(new SecurityRequest(credentialsForVerification, securityRequest.getTimestamp()));
                    // storing the result in our cache
                    alreadyValidatedCredentialsCache.put(partialPolicyCredentials, freshValidationStatus);
                    // success, these credentials satisfy security requirements
                    if (freshValidationStatus == ValidationStatus.VALID)
                        validatedCredentials++;
                    else
                        log.debug(freshValidationStatus);
                } catch (SecurityHandlerException e) {
                    // validation failed, storing with unknown status
                    log.debug(e);
                    alreadyValidatedCredentialsCache.put(partialPolicyCredentials, ValidationStatus.UNKNOWN);
                }
            }

            // all credentials need to be valid to confirm the policy access
            if (validatedCredentials == neededCredentials)
                accessiblePolicies.add(authorizedPolicy.getKey());
        }

        // resources to which the given security request grants access
        return accessiblePolicies;
    }

    @Override
    public SecurityRequest generateSecurityRequestUsingLocalCredentials() throws
            SecurityHandlerException {
        Set<AuthorizationCredentials> authorizationCredentials = new HashSet<>();
        HomeCredentials coreCredentials = getLocalAAMCredentials().homeCredentials;

        authorizationCredentials.add(new AuthorizationCredentials(coreCredentials.homeToken, coreCredentials.homeAAM, coreCredentials));
        try {
            return MutualAuthenticationHelper.getSecurityRequest(authorizationCredentials, false);
        } catch (NoSuchAlgorithmException e) {
            log.error(e);
            throw new SecurityHandlerException("Failed to generate security request: " + e.getMessage());
        }
    }

    @Override
    public String generateServiceResponse() throws
            SecurityHandlerException {
        BoundCredentials localAAMBoundCredentials = getLocalAAMCredentials();
        try {
            // generating the service response
            return MutualAuthenticationHelper.getServiceResponse(localAAMBoundCredentials.homeCredentials.privateKey, new Date().getTime());
        } catch (NoSuchAlgorithmException e) {
            log.error(e);
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
     * @return required for authorizing operations in the local AAM
     * @throws SecurityHandlerException on error
     */
    @Override
    public BoundCredentials getLocalAAMCredentials() throws
            SecurityHandlerException {
        BoundCredentials localAAMBoundCredentials = securityHandler.getAcquiredCredentials().get(localAAM.getAamInstanceId());
        if (localAAMBoundCredentials == null) {
            // making sure a proper certificate is in the keystore
            securityHandler.getCertificate(
                    localAAM,
                    componentOwnerUsername,
                    componentOwnerPassword,
                    combinedClientIdentifier);
            localAAMBoundCredentials = securityHandler.getAcquiredCredentials().get(localAAM.getAamInstanceId());
        }

        //checking if aam certificate changed during the component runtime

        Certificate platformCertificate = securityHandler.getComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME,
                localAAM.getAamInstanceId());
        if (!platformCertificate.getCertificateString().equals(
                localAAMBoundCredentials.homeCredentials.homeAAM.getAamCACertificate().getCertificateString())) {
            log.error(SecurityHandlerException.AAM_CERTIFICATE_DIFFERENT_THAN_IN_KEYSTORE);
            throw new SecurityHandlerException(SecurityHandlerException.AAM_CERTIFICATE_DIFFERENT_THAN_IN_KEYSTORE);
        }

        // check that we have a valid token
        boolean isLocalTokenRefreshNeeded = false;
        try {
            if (localAAMBoundCredentials.homeCredentials.homeToken == null
                    || JWTEngine.validateTokenString(localAAMBoundCredentials.homeCredentials.homeToken.getToken()) != ValidationStatus.VALID) {
                isLocalTokenRefreshNeeded = true;
            }
        } catch (ValidationException e) {
            log.debug(e);
            isLocalTokenRefreshNeeded = true;
        }

        // fetching the local token using the security handler
        if (isLocalTokenRefreshNeeded) {
            // gets the token and puts it in the wallet
            try {
                try {
                    securityHandler.login(localAAM);
                } catch (SecurityHandlerException e) {
                    if (e.getStatusCode().equals(HttpStatus.UNAUTHORIZED)) {
                        // we need to refresh our certificate
                        securityHandler.getCertificate(
                                localAAM,
                                componentOwnerUsername,
                                componentOwnerPassword,
                                combinedClientIdentifier);
                        // and trying to refresh the token with the new credentials
                        securityHandler.login(localAAM);
                    }
                }
                // fetching updated token from the wallet
                localAAMBoundCredentials = securityHandler.getAcquiredCredentials().get(localAAM.getAamInstanceId());
            } catch (ValidationException e) {
                log.error(e);
                throw new SecurityHandlerException("Can't refresh the components LocalAAM HOME token", e);
            }

        }
        return localAAMBoundCredentials;
    }

    @Override
    public Map<String, OriginPlatformGroupedPlatformMisdeedsReport> getOriginPlatformGroupedPlatformMisdeedsReports(Optional<String> resourcePlatformFilter,
                                                                                                                    Optional<String> searchOriginPlatformFilter) throws
            SecurityHandlerException {
        Map<String, String> params = new HashMap<>();
        resourcePlatformFilter.ifPresent(value -> params.put("platformId", value));
        searchOriginPlatformFilter.ifPresent(val -> params.put("getSecurityEnabledADMClient", val));
        try {
            return this.getSecurityEnabledADMClient().getMisdeedsGroupedByPlatform(params);
        } catch (FeignException fe) {
            throw handleFeignExceptions(fe);
        }
    }

    @Override
    public Map<String, FederationGroupedPlatformMisdeedsReport> getFederationGroupedPlatformMisdeedsReports(Optional<String> resourcePlatformFilter,
                                                                                                            Optional<String> federationId) throws
            SecurityHandlerException {
        Map<String, String> params = new HashMap<>();
        resourcePlatformFilter.ifPresent(value -> params.put("platformId", value));
        federationId.ifPresent(v -> params.put("federationId", v));
        try {
            return this.getSecurityEnabledADMClient().getMisdeedsGroupedByFederations(params);
        } catch (FeignException fe) {
            throw handleFeignExceptions(fe);
        }
    }

    private SecurityHandlerException handleFeignExceptions(FeignException fe) throws
            SecurityHandlerException {
        switch (fe.status()) {
            case 400:
                log.error("Bad request");
                throw new SecurityHandlerException("Bad/malformed request was sent to the ADM", fe);
            case 401:
                log.error("Failed to authorize the request in the core");
                throw new SecurityHandlerException("Failed to authorize the request", fe);
            case 500:
                log.error("Service Error");
                throw new SecurityHandlerException("ADM Service error", fe);
            default:
                throw new SecurityHandlerException("Unexpected happened", fe);
        }
    }

    private synchronized IFeignADMComponentClient getSecurityEnabledADMClient() throws
            SecurityHandlerException {
        if (admComponentClient == null)
            admComponentClient = SymbioteComponentClientFactory.createClient(
                    this.getSecurityHandler().getCoreAAMInstance().getAamAddress() + SecurityConstants.ADM_PREFIX,
                    IFeignADMComponentClient.class,
                    "adm",
                    SecurityConstants.CORE_AAM_INSTANCE_ID,
                    this);
        return admComponentClient;
    }
}
