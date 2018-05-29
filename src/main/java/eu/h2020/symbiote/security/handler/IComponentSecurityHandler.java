package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.SecurityCredentials;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;

import java.util.Map;
import java.util.Set;

/**
 * Symbiote Components Security Handler interface proposed for Release 3 of SymbIoTe.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Jose Antonio Sanchez Murillo (Atos)
 */
public interface IComponentSecurityHandler {

    /**
     * Used by a service to filter the {@link SecurityRequest#getSecurityCredentials()} to only those relevant to the business request,
     * namely satisfying any of the given {@link IAccessPolicy} and performing full verification of the refined {@link SecurityRequest}
     *
     * @param accessPolicies  of the resources/operations that need to be checked against the given {@link SecurityRequest}
     * @param securityRequest that might satisfy the given access policies
     * @return set of identifiers of policies (e.g. resources identifiers) whose access policies are satisfied with the security verified {@link SecurityRequest#getSecurityCredentials()}
     */
    Set<String> getSatisfiedPoliciesIdentifiers(Map<String, IAccessPolicy> accessPolicies,
                                                SecurityRequest securityRequest);

    /**
     * Used by a service to filter the {@link SecurityRequest#getSecurityCredentials()} to only those relevant to the business request,
     * namely satisfying any of the given {@link IAccessPolicy} and performing full verification of the refined {@link SecurityRequest}
     *
     * @param accessPolicies                   of the resources/operations that need to be checked against the given {@link SecurityRequest}
     * @param securityRequest                  that might satisfy the given access policies
     * @param alreadyValidatedCredentialsCache used to persist state of remotely (in)validated credentials. Must be an empty map each time the securityRequest changes.
     * @return set of identifiers of policies (e.g. resources identifiers) whose access policies are satisfied with the security verified {@link SecurityRequest#getSecurityCredentials()}
     */
    Set<String> getSatisfiedPoliciesIdentifiers(Map<String, IAccessPolicy> accessPolicies,
                                                SecurityRequest securityRequest,
                                                Map<SecurityCredentials, ValidationStatus> alreadyValidatedCredentialsCache);


    /**
     * Used by a service to generate the response payload to be encapsulated in a JWS required by
     * the application to confirm the service authenticity.
     *
     * @return the required payload that should be attached next to the components API business response so that the client can verify that the service is legitimate
     */
    String generateServiceResponse() throws SecurityHandlerException;

    /**
     * Used by a component to generate the {@link SecurityRequest} needed to authorize operations in the Symbiote Core to be attached to the business query
     * so that the service can confirm that the client should posses provided tokens
     *
     * @return the required payload for client's authentication and authorization
     */
    SecurityRequest generateSecurityRequestUsingLocalCredentials() throws
            SecurityHandlerException;

    /**
     * Used by a component to verify that the other components response was legitimate... e.g. to handle the service response encapsulated in a JWS.
     *
     * @param serviceResponse     that should prove the service's authenticity
     * @param componentIdentifier from which the service response was received
     * @param platformIdentifier  to which the component belongs ({@link SecurityConstants#CORE_AAM_INSTANCE_ID} for Symbiote core components)
     * @return true if the service is genuine
     */
    boolean isReceivedServiceResponseVerified(String serviceResponse,
                                              String componentIdentifier,
                                              String platformIdentifier)
            throws SecurityHandlerException;

    /**
     * @return if the component owner wants to use the SH directly
     */
    ISecurityHandler getSecurityHandler();

    /**
     * gets the credentials from the wallet, if missing then issues them and adds to the wallet
     *
     * @return required for authorizing operations in the local AAM
     * @throws SecurityHandlerException on error
     */
    BoundCredentials getLocalAAMCredentials() throws
            SecurityHandlerException;
}
