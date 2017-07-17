package eu.h2020.symbiote.security.handler.session;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.handler.SecurityHandler;

import java.util.HashMap;
import java.util.Map;

/**
 * @deprecated use @{@link Map} of {@link BoundCredentials} grouped by @{@link AAM} instead of this class
 */
@Deprecated
public class SessionInformation {
    // todo R3 rework to have a wallet of tokens grouped by issuing AAMs and support multiple Platform (home) tokens
    private Token homeToken;
    private Token coreToken;
    // todo R3 rename to federated tokens
    private Map<String, Token> foreignTokens = new HashMap<>();

    /**
     * TODO R3 add support for handling the collection received from @{@link SecurityHandler#getAvailableAAMs()} in a map grouped by aamsIds
     */
    public SessionInformation() {
    }

    public Token getHomeToken() {
        return homeToken;
    }

    public void setHomeToken(Token homeToken) {
        this.homeToken = homeToken;
    }

    public Token getCoreToken() {
        return coreToken;
    }

    public void setCoreToken(Token coreToken) {
        this.coreToken = coreToken;
    }

    public Map<String, Token> getForeignTokens() {
        return foreignTokens;
    }

    public void setForeignTokens(Map<String, Token> foreignTokens) {
        this.foreignTokens = foreignTokens;
    }

    public Token getForeignToken(String aamIdentifier) {
        return foreignTokens.get(aamIdentifier);
    }

    public void setForeignToken(String aamIdentifier, Token token) {
        foreignTokens.put(aamIdentifier, token);
    }

}
