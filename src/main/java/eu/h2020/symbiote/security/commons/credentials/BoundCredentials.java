package eu.h2020.symbiote.security.commons.credentials;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.communication.payloads.AAM;

import java.util.HashMap;
import java.util.Map;

/**
 * Credentials bound with a particular AAM
 */
public class BoundCredentials {

    /**
     * credentials issued by the AAM if the user has an account in it
     */
    public HomeCredentials homeCredentials;
    /**
     * Map of foreign tokens that were acquired using this homeToken
     */
    public Map<AAM, Token> foreignTokens = new HashMap<>();

    public BoundCredentials(HomeCredentials homeCredentials) {
        this.homeCredentials = homeCredentials;
    }
}
