package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
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
     * Validates the security request that was received on the API next to the component's business request
     *
     * @param securityRequest to be validated
     * @return ValidationStatus#VALID if the validation passed and the request can be used for ABAC resolution, on any other status the component must stop processing the request!!!
     * @throws SecurityHandlerException on error
     */
    ValidationStatus isReceivedSecurityRequestValid(SecurityRequest securityRequest) throws
            SecurityHandlerException;

    /**
     * Used by the component to verify that the other components response was legitimate... e.g. to handle the service response encapsulated in a JWS.
     *
     * @param serviceResponse    that should prove the service's authenticity
     * @param serviceCertificate from the component that the last operation was requested. Can be found in the @{@link AAM#componentCertificates}
     * @return true if the service is genuine
     */
    boolean isReceivedServiceResponseVerified(String serviceResponse,
                                              Certificate serviceCertificate) throws SecurityHandlerException;

    /**
     *
     * @param accessPolicies  of the resources that need to be checked against the tokens
     * @param securityRequest that might satisfy the access policies of the resources
     * @return set of resources (their identifiers) whose access policies are satisfied with the given tokens
     */
    Set<String> getAuthorizedResourcesIdentifiers(Map<String, IAccessPolicy> accessPolicies,
                                                  SecurityRequest securityRequest) throws SecurityHandlerException;

    /**
     * Used by the component to generate the security request needed to authorize operations in the symbiote Core to be attached to the business query
     * so that the service can confirm that the client should posses provided tokens
     *
     * @return the required payload for client's authentication and authorization
     */
    SecurityRequest generateSecurityRequestUsingCoreCredentials() throws
            SecurityHandlerException;

    /**
     * Used by the service to generate the response payload to be encapsulated in a JWS required by
     * the application to confirm the service authenticity.
     *
     * @return the required payload that should be attached next to the components API business response so that the client can verify that the service is legitimate
     */
    String generateServiceResponse() throws SecurityHandlerException;

    /**
     * @return if the component owner wants to use the SH directly
     */
    ISecurityHandler getSecurityHandler();
}
