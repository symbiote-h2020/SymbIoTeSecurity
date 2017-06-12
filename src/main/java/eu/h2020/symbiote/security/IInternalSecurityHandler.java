package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.policy.IAccessPolicy;
import eu.h2020.symbiote.security.token.Token;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by Mikołaj on 12.06.2017.
 */
public interface IInternalSecurityHandler extends ISecurityHandler {

    /**
     * @param accessPolicies      of the resources that need to be checked against the tokens
     * @param authorizationTokens that might satisfy the access policies of the resources
     * @return list of resources (their identifiers) whose access policies are satisfied with the given tokens
     */
    default List<String> getAuthorizedResourcesIdentifiers(Map<String, IAccessPolicy> accessPolicies,
                                                           List<Token> authorizationTokens) {

        List<String> authorizedResources = new ArrayList<>();
        for (Map.Entry<String, IAccessPolicy> resource : accessPolicies.entrySet()) {
            if (resource.getValue().isSatisfiedWith(authorizationTokens))
                authorizedResources.add(resource.getKey());
        }
        return authorizedResources;
    }
}
