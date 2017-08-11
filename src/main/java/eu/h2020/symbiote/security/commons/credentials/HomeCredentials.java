package eu.h2020.symbiote.security.commons.credentials;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.communication.payloads.AAM;

import java.security.PrivateKey;

/**
 * Credentials issued for a user that has account in the given AAM
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class HomeCredentials {
    /**
     * AAM the user has account in.
     */
    public final AAM homeAAM;
    /**
     * the username for your account in the home AAM
     */
    public final String username;
    /**
     * user's client identifier
     */
    public final String clientIdentifier;
    /**
     * Certificate of this client
     */
    public final Certificate certificate;
    /**
     * matching the public key in the certificate
     */
    public final PrivateKey privateKey;
    /**
     * token acquired from your home AAM
     */
    public Token homeToken = null;

    public HomeCredentials(AAM homeAAM, String username, String clientIdentifier, Certificate certificate, PrivateKey
            privateKey) {
        this.homeAAM = homeAAM;
        this.username = username;
        this.clientIdentifier = clientIdentifier;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }
}
