package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.ABACResolverResponse;
import eu.h2020.symbiote.security.communication.payloads.SecurityCredentials;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Created by Nemanja on 18.08.2017.
 * <p>
 * Utility class that provides access policy validation functioncality for required set of resources
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class ABACPolicyHelper {

    private ABACPolicyHelper() {
    }

    /**
     * TODO @Nemanja please improve to return ResourcesIdentifiers with Credentials that satisfied those resources' policies -> will allow optimistic validation in next step
     *
     * @param accessPolicies  of the resources that need to be checked against the tokens
     * @param securityRequest container for tokens and user credentials which will be checked against access policies
     * @return set of resources (their identifiers) whose access policies are satisfied with the given credentials
     */
    public static ABACResolverResponse checkRequestedOperationAccess(Map<String, IAccessPolicy> accessPolicies,
                                                                     SecurityRequest securityRequest) {
        ABACResolverResponse abacResp = new ABACResolverResponse();
        // extracting credentials from the security request
        Map<Token, SecurityCredentials> authzCredentials = new HashMap<>(securityRequest.getSecurityCredentials().size());
        for (SecurityCredentials securityCredentials : securityRequest.getSecurityCredentials()) {
            try {
                authzCredentials.put(new Token(securityCredentials.getToken()), securityCredentials);
            } catch (ValidationException e) {
                // on purpose skipping corrupted/expired tokens instead of jumping out of the whole procedure
                // as other tokens might be perfectly valid for the business request
                e.printStackTrace();
            }
        }

        // not valid tokens found in the request so no resolution will happen
        if (authzCredentials.isEmpty())
            return abacResp;

        // attempting to resolve the access policy
        if (accessPolicies != null) {
            for (Map.Entry<String, IAccessPolicy> resource : accessPolicies.entrySet()) {
                if (resource.getValue() != null) {
                    Set<Token> validTokens = resource.getValue().isSatisfiedWith(authzCredentials.keySet());
                    //Check if any valid token is found for the access policy
                    if (validTokens.isEmpty()) {
                        // the tokens do not match this resource's access policy
                        continue;
                    }
                    // access to the resource is authorized
                    abacResp.getAuthorizedResourcesIdentifiers().add(resource.getKey());
                    // with the following tokens
                    for (Token t : validTokens) {
                        abacResp.getAuthorizationCredentials().add(authzCredentials.get(t));
                    }
                } else {
                    // resource has a null access policy and therefore any token should satisfy it
                    abacResp.getAuthorizedResourcesIdentifiers().add(resource.getKey());
                    // adding a token if the credentials set is empty
                    if (abacResp.getAuthorizationCredentials().isEmpty())
                        abacResp.getAuthorizationCredentials().add(authzCredentials.values().iterator().next());
                }
            }
        }
        return abacResp;
    }
}
