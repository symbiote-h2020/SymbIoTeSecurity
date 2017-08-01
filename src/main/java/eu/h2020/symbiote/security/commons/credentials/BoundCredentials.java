package eu.h2020.symbiote.security.commons.credentials;

import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;

/**
 * Credentials bound with a particular AAM
 */
public class BoundCredentials {
    /**
     * the AAM the credentialsWallet are bound to
     */
    public final AAM aam;
    /**
     * credentials issued by the AAM if the user has an account in it
     */
    public HomeCredentials homeCredentials;

    public BoundCredentials(AAM aam) {
        this.aam = aam;
    }
}
