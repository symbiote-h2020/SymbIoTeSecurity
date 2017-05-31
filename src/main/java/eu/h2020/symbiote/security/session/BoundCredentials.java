package eu.h2020.symbiote.security.session;

import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.token.Token;

import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Credentials bound with a particular AAM
 */
public class BoundCredentials {
    /**
     * the AAM the credentialsWallet are bound to
     */
    public final AAM aam;
    /**
     * the username for your account in the home AAM
     */
    public String username = "";
    /**
     * token acquired from your home AAM
     */
    public Token homeToken = null;
    /**
     * Map of foreign tokens that were acquired using this homeToken
     */
    public Map<AAM, Token> foreignTokens = new HashMap<>();
    /**
     * Certificate of this client
     */
    public Certificate certificate = null;
    /**
     * matching the public key in the certificate
     */
    public PrivateKey privateKey = null;

    public BoundCredentials(AAM aam) {
        this.aam = aam;
    }
}
