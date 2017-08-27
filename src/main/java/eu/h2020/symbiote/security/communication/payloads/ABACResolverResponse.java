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
    private Set<Token> validTokens;

    public ABACResolverResponse() {
        this.availableResources = new HashSet<String>();
        this.validTokens = new HashSet<Token>();
    }

    public ABACResolverResponse(Set<String> availableResources, Set<Token> validTokens) {
        this.availableResources = availableResources;
        this.validTokens = validTokens;
    }

    public Set<String> getAvailableResources() {
        return availableResources;
    }

    public void setAvailableResources(Set<String> availableResources) {
        this.availableResources = availableResources;
    }

    public Set<Token> getValidTokens() {
        return validTokens;
    }

    public void setValidTokens(Set<Token> validTokens) {
        this.validTokens = validTokens;
    }
}
