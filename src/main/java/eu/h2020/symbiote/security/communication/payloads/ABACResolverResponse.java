package eu.h2020.symbiote.security.communication.payloads;

import java.util.HashSet;
import java.util.Set;

/**
 * Class that defines structure of payload received as response on Tokens authorization against access policies
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class ABACResolverResponse {

    private Set<String> availableResources;
    private Set<SecurityCredentials> authorizationCredentials;

    public ABACResolverResponse() {
        this.availableResources = new HashSet<>();
        this.authorizationCredentials = new HashSet<>();
    }

    public ABACResolverResponse(Set<String> availableResources, Set<SecurityCredentials> authorizationCredentials) {
        this.availableResources = availableResources;
        this.authorizationCredentials = authorizationCredentials;
    }

    public Set<String> getAuthorizedResourcesIdentifiers() {
        return availableResources;
    }

    public void setAvailableResources(Set<String> availableResources) {
        this.availableResources = availableResources;
    }

    public Set<SecurityCredentials> getAuthorizationCredentials() {
        return authorizationCredentials;
    }

    public void setAuthorizationCredentials(Set<SecurityCredentials> authorizationCredentials) {
        this.authorizationCredentials = authorizationCredentials;
    }
}
