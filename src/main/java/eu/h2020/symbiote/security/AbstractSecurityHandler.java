package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.certificate.ECDSAHelper;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.rest.clients.CoreAAMClient;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.session.BoundCredentials;
import eu.h2020.symbiote.security.token.Token;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.SignedObject;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Abstract implementation of the {@link ISecurityHandler} that all concrete implementations should extend from.
 */
public class AbstractSecurityHandler implements ISecurityHandler {

    private final String coreAAMAddress;
    private final String keystorePassword;
    private final String clientId;
    protected Map<AAM, BoundCredentials> credentialsWallet;
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
        credentialsWallet = new HashMap<>();
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
    public Token login(AAM homeAAM, SignedObject loginRequest) throws SecurityHandlerException {
        return null;
    }

    @Override
    public Map<AAM, Token> login(List<AAM> foreignAAMs, Token homeToken, Optional<Certificate> certificate)
            throws SecurityHandlerException {
        return null;
    }

    @Override
    public void logout() {
        for (BoundCredentials credentials : credentialsWallet.values()) {
            credentials.homeToken = null;
            credentials.foreignTokens.clear();
        }

    }

    @Override
    public Certificate getCertificate(String username,
                                      String password,
                                      String clientId,
                                      PKCS10CertificationRequest clientCSR)
            throws SecurityHandlerException {
        return null;
    }

    @Override
    public List<AAM> getAvailableAAMs() throws SecurityHandlerException {
        CoreAAMClient coreAAMClient = new CoreAAMClient(coreAAMAddress);
        return coreAAMClient.getAvailableAAMs();
    }

    @Override
    public ValidationStatus validate(AAM validationAuthority, String token, Optional<Certificate> certificate) {
        return null;
    }
}
