package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.certificate.ECDSAHelper;
import eu.h2020.symbiote.security.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.session.BoundCredentials;
import eu.h2020.symbiote.security.token.Token;

import java.util.HashMap;
import java.util.Map;

/**
 * Abstract implementation of the {@link ISecurityHandler} that all concrete implementations should extend from.
 */
public abstract class AbstractSecurityHandler implements ISecurityHandler {

    // client configuration
    private final String coreAAMAddress;
    private final String keystorePassword;
    private final String clientId;
    // credentials cache
    protected Token guestToken = null;
    protected Map<AAM, BoundCredentials> credentialsWallet = new HashMap<>();
    private boolean isOnline;


    /**
     * Creates a new instance of the Security Handler
     *
     * @param coreAAMAddress   from where the Security Handler can resolve the Symbiote se
     * @param keystorePassword required to unlock the persisted keystore for this client
     * @param clientId         user defined identifier of this Security Handler
     * @param isOnline         if the security Handler has access to the Internet and SymbIoTe Core
     * @throws SecurityHandlerException on instantiation errors
     */
    public AbstractSecurityHandler(String coreAAMAddress,
                                   String keystorePassword,
                                   String clientId,
                                   boolean isOnline)
            throws SecurityHandlerException {
        // enabling support for elliptic curve certificates
        ECDSAHelper.enableECDSAProvider();

        // rest of the constructor code
        this.coreAAMAddress = coreAAMAddress;
        this.keystorePassword = keystorePassword;
        this.clientId = clientId;
        this.isOnline = isOnline;

        buildCredentialsWallet(isOnline);
    }

    private void buildCredentialsWallet(boolean isOnline) throws SecurityHandlerException {
        if (isOnline) {
            // fetch available AAMs from the SymbIoTe Core
            for (AAM aam : this.getAvailableAAMs()) {
                BoundCredentials boundCredentials = new BoundCredentials(aam);
                // todo access the persistent storage, retrieve BoundCredentials for this AAM and fill them properly
                credentialsWallet.put(aam, boundCredentials);
            }
        } else {
            // todo access the persistent storage and retrieve all the BoundCredentials that were stored there
        }
    }

    @Override
    public void clearCachedTokens() {
        guestToken = null;
        for (BoundCredentials credentials : credentialsWallet.values()) {
            credentials.homeToken = null;
            credentials.foreignTokens.clear();
        }

    }
}
