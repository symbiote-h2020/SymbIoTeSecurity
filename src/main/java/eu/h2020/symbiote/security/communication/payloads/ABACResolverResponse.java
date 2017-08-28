package eu.h2020.symbiote.security.communication.payloads;

import eu.h2020.symbiote.security.commons.Token;

import java.util.HashSet;
import java.util.Set;

/**
 * Class that defines structure of payload received as response on Tokens authorization against access policies
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class ABACResolverResponse {

    private Set<String> availableResources;
    private Set<SecurityCredentials> validCredentials;

    public ABACResolverResponse() {
        this.availableResources = new HashSet<String>();
        this.validCredentials = new HashSet<SecurityCredentials>();
    }

    public ABACResolverResponse(Set<String> availableResources, Set<SecurityCredentials> validCredentials) {
        this.availableResources = availableResources;
        this.validCredentials = validCredentials;
    }

    public Set<String> getAvailableResources() {
        return availableResources;
    }

    public void setAvailableResources(Set<String> availableResources) {
        this.availableResources = availableResources;
    }

    public Set<SecurityCredentials> getValidCredentials() {
        return validCredentials;
    }

    public void setValidCredentials(Set<SecurityCredentials> validCredentials) {
        this.validCredentials = validCredentials;
    }
}
