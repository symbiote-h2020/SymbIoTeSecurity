package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.AAM;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * just a placeholder class, to be deleted by Jose Antonio
 */
@Deprecated
public class DummySecurityHandler extends AbstractSecurityHandler {
    /**
     * Creates a new instance of the Security Handler
     *
     * @param coreAAMAddress   from where the Security Handler can resolve the Symbiote se
     * @param keystorePassword required to unlock the persisted keystore for this client
     * @param clientId         user defined identifier of this Security Handler
     * @param isOnline         if the security Handler has access to the Internet and SymbIoTe Core
     * @throws SecurityHandlerException on instantiation errors
     */
    public DummySecurityHandler(String coreAAMAddress, String keystorePassword, String clientId, boolean isOnline) throws
            SecurityHandlerException {
        super(coreAAMAddress, keystorePassword, clientId, isOnline);
    }

    @Override
    public Map<String, AAM> getAvailableAAMs() throws SecurityHandlerException {
        return null;
    }

    @Override
    public Token login(HomeCredentials homeCredentials) throws SecurityHandlerException {
        return null;
    }

    @Override
    public Map<AAM, Token> login(List<AAM> foreignAAMs, HomeCredentials homeCredentials) throws
            SecurityHandlerException {
        return null;
    }

    @Override
    public Token loginAsGuest(AAM aam) {
        return null;
    }

    @Override
    public Certificate getCertificate(AAM homeAAM, String username, String password, String clientId, String clientCSR) throws
            SecurityHandlerException {
        return null;
    }

    @Override
    public ValidationStatus validate(AAM validationAuthority, String token, Optional<String> clientCertificate, Optional<String> clientCertificateSigningAAMCertificate, Optional<String> foreignTokenIssuingAAMCertificate) {
        return null;
    }
}
