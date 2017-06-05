package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.policy.IAccessPolicy;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.SignedObject;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;

/**
 * Security Handler interface proposed for Release 3 of SymbIoTe.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Pietro Tedeschi (CNIT)
 */
public interface ISecurityHandler {

    /**
     * Retrieves your home token from the given AAM you have account in.
     *
     * @param homeAAM      to request the token from
     * @param loginRequest containing the username and client id signed with your private Key
     * @return home token
     * @throws SecurityHandlerException on operation error
     */
    Token login(AAM homeAAM, SignedObject loginRequest) throws SecurityHandlerException;

    /**
     * Login to foreign AAMs (you don't have account in) using home token.
     *
     * @param foreignAAMs to get the Tokens from
     * @param homeToken   to use as login credentialsWallet
     * @param certificate if the operation is in an intranet environment, then the user needs to provide the
     *                    certificate matching the one from the homeToken
     * @return map of the foreign tokens that were acquired using a given home token
     * @throws SecurityHandlerException on operation error
     */
    Map<AAM, Token> login(List<AAM> foreignAAMs, Token homeToken, Optional<Certificate> certificate)
            throws SecurityHandlerException;

    /**
     * Removes all the acquired tokens from memory
     */
    void logout();

    /**
     * Used to acquire a certificate for this client from the home AAM
     *
     * @param username  of the user in the home AAM
     * @param password  of the user in the home AAM
     * @param clientId  that will be bound with the user and this client
     * @param clientCSR required to issue a certificate for this client
     * @return certificate used by this client for challenge-response operations
     * @throws SecurityHandlerException on operation error
     */
    Certificate getCertificate(String username,
                               String password,
                               String clientId,
                               PKCS10CertificationRequest clientCSR)
            throws SecurityHandlerException;


    /**
     * @return list of all currently available security entrypoints to symbiote (getCertificate, login, token
     * validation)
     * @throws SecurityHandlerException on operation error
     */
    List<AAM> getAvailableAAMs() throws SecurityHandlerException;


    /**
     * @param token       to be validated
     * @param certificate if the operation is in an intranet environment, then the user needs to provide the
     *                    certificate matching the one from the homeToken
     * @return validation status of the given token
     */
    ValidationStatus validate(AAM validationAuthority, String token, Optional<Certificate> certificate);


    /**
     * @param accessPolicies      of the resources that need to be checked against the tokens
     * @param authorizationTokens that might satisfy the access policies of the resources
     * @return list of resources (their identifiers) whose access policies are satisfied with the given tokens
     */
    default List<String> getAuthorizedResourcesIdentifiers(Map<String, IAccessPolicy> accessPolicies,
                                                           List<Token> authorizationTokens) {
        List<String> authorizedResources = new ArrayList<>();
        for (Entry<String, IAccessPolicy> resource : accessPolicies.entrySet()) {
            if (resource.getValue().isSatisfiedWith(authorizationTokens))
                authorizedResources.add(resource.getKey());
        }
        return authorizedResources;
    }
}