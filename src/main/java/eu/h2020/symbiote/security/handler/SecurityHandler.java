package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

/**
 * Abstract implementation of the {@link ISecurityHandler} that all concrete implementations should
 * extend from.
 */
public class SecurityHandler implements ISecurityHandler {

    private static final Log logger = LogFactory.getLog(SecurityHandler.class);

    private final String keystorePath;
    private final String keystorePassword;
    private final String homeAAMAddress;

    private final String platformId;
    //In memory credentials wallet by Home AAM id -> Client ID -> User ID -> Credentials
    private Map<String, BoundCredentials> credentialsWallet =
            new HashMap<>();
    //Associate tokens with credentials
    private Map<String, BoundCredentials> tokenCredentials = new HashMap<>();
    private AAM coreAAM = null;

    /**
     * Creates a new instance of end-user oriented Security Handler
     *
     * @param keystorePath     required to find the persisted keystore for this client
     * @param keystorePassword required to unlock the persisted keystore for this client
     * @param homeAAMAddress   needed to initialize the client
     * @throws SecurityHandlerException on instantiation errors
     */
    public SecurityHandler(String keystorePath,
                           String keystorePassword,
                           String homeAAMAddress)
            throws SecurityHandlerException {
        this(keystorePath, keystorePassword, homeAAMAddress, "");
    }

    /**
     * To be used only by the {@link eu.h2020.symbiote.security.ComponentSecurityHandlerFactory} !!!
     *
     * @param keystorePath     required to find the persisted keystore for this client
     * @param keystorePassword required to unlock the persisted keystore for this client
     * @param homeAAMAddress   needed to initialize the client
     * @param platformId       used by the {@link ComponentSecurityHandler} to identify its local AAM
     * @throws SecurityHandlerException
     */
    public SecurityHandler(String keystorePath,
                           String keystorePassword,
                           String homeAAMAddress,
                           String platformId)
            throws SecurityHandlerException {
        // enabling support for elliptic curve certificates
        ECDSAHelper.enableECDSAProvider();

        // rest of the constructor code
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.homeAAMAddress = homeAAMAddress;
        this.platformId = platformId;

        try {
            buildCredentialsWallet();
        } catch (Exception e) {
            throw new SecurityHandlerException("Error generating credentials wallet", e);
        }
    }

    private static KeyStore getKeystore(String path, String password) throws
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {

        char[] pw = password.toCharArray();
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());

        File ksFile = new File(path);

        if (!ksFile.exists()) {
            trustStore.load(null, pw);

            // Store away the keystore.
            FileOutputStream fos = new FileOutputStream(ksFile);
            trustStore.store(fos, pw);
            fos.close();
        }

        FileInputStream fIn = new FileInputStream(ksFile);
        trustStore.load(fIn, password.toCharArray());

        fIn.close();
        return trustStore;
    }

    public Map<String, AAM> getAvailableAAMs() throws SecurityHandlerException {
        return getAvailableAAMs(coreAAM);
    }

    public Map<String, AAM> getAvailableAAMs(AAM homeAAM) throws SecurityHandlerException {
        return getAvailableAAMs(homeAAM.getAamAddress());
    }

    public Map<String, AAM> getAvailableAAMs(String aamAddress) throws SecurityHandlerException {
        // end-client
        if (platformId.isEmpty()) {
            try {
                return ClientFactory.getAAMClient(aamAddress).getAvailableAAMs().getAvailableAAMs();
            } catch (AAMException e) { // communication fail with the AAM
                throw new SecurityHandlerException(e.getMessage(), e);
            }
        }
        // local component option
        try {
            return ClientFactory.getAAMClient(homeAAMAddress).getAAMsInternally().getAvailableAAMs();
        } catch (AAMException e) {
            // failed to communicate over new API
            try {
                // trying fallback to old API when AAM wasn't updated to the new protocol
                return ClientFactory.getAAMClient(homeAAMAddress).getAvailableAAMs().getAvailableAAMs();
            } catch (AAMException e2) { // communication fail with the AAM
                throw new SecurityHandlerException(e.getMessage(), e2);
            }
        }
    }

    public Token login(AAM homeAAMId) throws SecurityHandlerException, ValidationException {
        BoundCredentials credentials = credentialsWallet.get(homeAAMId.getAamInstanceId());

        if (credentials != null && credentials.homeCredentials != null &&
                credentials.homeCredentials.privateKey != null) {
            try {
                String homeToken = ClientFactory.getAAMClient(homeAAMId.getAamAddress()).getHomeToken(
                        CryptoHelper.buildHomeTokenAcquisitionRequest(credentials.homeCredentials));
                credentials.homeCredentials.homeToken = new Token(homeToken);
                tokenCredentials.put(homeToken, credentials);
                return credentials.homeCredentials.homeToken;
            } catch (WrongCredentialsException e) {
                throw new SecurityHandlerException("Wrong credentials provided for log in", e);
            } catch (JWTCreationException e) {
                throw new SecurityHandlerException("Error creating log in token", e);
            } catch (MalformedJWTException e) {
                throw new SecurityHandlerException("Malformed token sent", e);
            } catch (AAMException e) { // communication fail with the AAM
                throw new SecurityHandlerException(e.getMessage(), e);
            }
        } else {
            throw new SecurityHandlerException("Can't find certificate for AAM " + homeAAMId.getAamInstanceId());
        }
    }

    public Map<AAM, Token> login(List<AAM> foreignAAMs, String homeToken)
            throws SecurityHandlerException {

        BoundCredentials credentials = tokenCredentials.get(homeToken);
        if (credentials != null && credentials.homeCredentials != null
                && credentials.homeCredentials.certificate != null) {

            String certificateStr = credentials.homeCredentials.certificate.getCertificateString();
            Map<AAM, Token> result = foreignAAMs.stream().collect(Collectors.toMap(aam -> aam, aam -> {
                try {
                    return new Token(ClientFactory.getAAMClient(aam.getAamAddress()).getForeignToken(homeToken,
                            Optional.ofNullable(certificateStr),
                            Optional.ofNullable(credentials.homeCredentials.homeAAM.getAamCACertificate().getCertificateString())));
                } catch (ValidationException e) {
                    logger.error("Invalid token returned for AAM " + aam.getAamInstanceId(), e);
                    return null;
                } catch (JWTCreationException e) {
                    logger.error("Error creating log in token", e);
                    return null;
                } catch (AAMException e) {
                    logger.error("Other error when communicating with the AAM occured" + e.getMessage(), e);
                    return null;
                }
            }));

            credentials.foreignTokens = result;
            return result;

        } else {
            throw new SecurityHandlerException("Can't find credentials for token " + homeToken);
        }

    }

    public Token loginAsGuest(AAM aam) throws ValidationException, SecurityHandlerException {
        try {
            return new Token(ClientFactory.getAAMClient(aam.getAamAddress()).getGuestToken());
        } catch (JWTCreationException e) {
            throw new SecurityHandlerException("Error creating log in token", e);
        } catch (AAMException e) { // communication fail with the AAM
            throw new SecurityHandlerException(e.getMessage(), e);
        }
    }

    public ValidationStatus validate(AAM validationAuthority, String token,
                                     Optional<String> clientCertificate,
                                     Optional<String> clientCertificateSigningAAMCertificate,
                                     Optional<String> foreignTokenIssuingAAMCertificate) throws
            SecurityHandlerException {


        try {
            return ClientFactory.getAAMClient(validationAuthority.getAamAddress()).validateCredentials(token,
                    clientCertificate,
                    clientCertificateSigningAAMCertificate,
                    foreignTokenIssuingAAMCertificate);
        } catch (AAMException e) { // communication fail with the AAM
            throw new SecurityHandlerException(e.getMessage(), e);
        }
    }

    @Override
    public Map<String, BoundCredentials> getAcquiredCredentials() {
        return credentialsWallet;
    }

    @Override
    public Certificate getComponentCertificate(String componentIdentifier, String platformIdentifier) throws
            SecurityHandlerException {
        AAMClient aamClient = ClientFactory.getAAMClient(homeAAMAddress);
        Certificate certificate;
        /*   temporarily disabling the cache as it causes service response validation errors
        TODO R4 add forced refresh on failed validation
        // checking cache
        if (credentialsWallet.containsKey(platformIdentifier)
                && credentialsWallet.get(platformIdentifier).homeCredentials.homeAAM.getComponentCertificates().containsKey(componentIdentifier))
          // fetching from wallet
          certificate = credentialsWallet.get(platformIdentifier).homeCredentials.homeAAM.getComponentCertificates().get(componentIdentifier);
        else {
        */
        // need to fetch fresh certificate
        try {
            certificate = new Certificate(aamClient.getComponentCertificate(componentIdentifier, platformIdentifier));
            //TODO: add new certificate to credentialWallet (create credWallet for platform if missing?)
        } catch (AAMException | CertificateException e) {
            logger.error(e);
            throw new SecurityHandlerException("Failed to fetch the component certificate from the AAM. " + e.getMessage());
        }
        return certificate;
    }

    @Override
    public AAM getCoreAAMInstance() {
        return coreAAM;
    }

    private void cacheCertificate(HomeCredentials credentials) {

        BoundCredentials bound = new BoundCredentials(credentials);
        bound.homeCredentials = credentials;

        credentialsWallet.put(credentials.homeAAM.getAamInstanceId(), bound);
    }

    @Override
    public void clearCachedTokens() {
        tokenCredentials = new HashMap<>();
        credentialsWallet.values().forEach(credential -> {
            credential.foreignTokens = new HashMap<>();
            credential.homeCredentials.homeToken = null;
        });
    }

    public Certificate getCertificate(AAM homeAAM, String username, String password,
                                      String clientId)
            throws SecurityHandlerException {
        if (homeAAM == null
                || homeAAM.getAamAddress().isEmpty()
                || homeAAM.getAamCACertificate().getCertificateString().isEmpty())
            throw new SecurityHandlerException("The AAM to request the client's certificate from is null has missing details address/certificate");
        if (username == null || username.isEmpty()
                || password == null || password.isEmpty()
                || clientId == null || clientId.isEmpty())
            throw new SecurityHandlerException("Missing username/password/clientId, those parameters must not be empty");

        if (!username.matches("^(([\\w-])+)$")) {
            throw new SecurityHandlerException("Username contains invalid characters");
        }
        try {
            KeyPair pair = CryptoHelper.createKeyPair();

            String csr;
            if (clientId.contains("@")) {
                String[] componentInfo = clientId.split("@");
                csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(
                        componentInfo[0], componentInfo[1], pair);
            } else {
                if (!clientId.matches("^(([\\w-])+)$")) {
                    throw new SecurityHandlerException("Client Id contains invalid characters");
                }
                csr = CryptoHelper.buildCertificateSigningRequestPEM(
                        homeAAM.getAamCACertificate().getX509(), username, clientId, pair);
            }

            CertificateRequest request = new CertificateRequest(username, password, clientId, csr);

            String certificateValue;
            try {
                certificateValue = ClientFactory.getAAMClient(homeAAM.getAamAddress())
                        .signCertificateRequest(request);
            } catch (AAMException e) { // communication fail with the AAM
                throw new SecurityHandlerException(e.getMessage(), e);
            }

            Certificate certificate = new Certificate(certificateValue);
            HomeCredentials credentials;
            if (clientId.contains("@")) {
                credentials = new HomeCredentials(homeAAM, clientId.split(illegalSign)[1], clientId.split(illegalSign)[0], certificate,
                        pair.getPrivate());
            } else {
                credentials = new HomeCredentials(homeAAM, username, clientId, certificate,
                        pair.getPrivate());
            }
            try {
                saveCertificate(credentials);
            } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
                throw new SecurityHandlerException("Error saving certificate in keystore");
            }
            cacheCertificate(credentials);


            return certificate;

        } catch (CertificateException | NotExistingUserException | ValidationException | InvalidArgumentsException e) {
            throw new SecurityHandlerException(e.getMessage(), e);
        } catch (IOException e) {
            throw new SecurityHandlerException("Error signing certificate request", e);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            throw new SecurityHandlerException("Error generating key pair", e);
        }

    }

    private KeyStore getKeystore() throws
            IOException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException {
        return getKeystore(keystorePath, keystorePassword);
    }

    /**
     * Read all certificates in the keystore and populate the credentialsWallet
     */
    private void buildCredentialsWallet() throws
            SecurityHandlerException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            IOException,
            UnrecoverableEntryException {

        KeyStore trustStore = getKeystore();

        Map<String, AAM> aamList = getAvailableAAMs(homeAAMAddress);
        if (aamList != null && !aamList.isEmpty()
                && aamList.get(SecurityConstants.CORE_AAM_INSTANCE_ID) != null) {
            coreAAM = aamList.get(SecurityConstants.CORE_AAM_INSTANCE_ID);
        } else {
            throw new SecurityHandlerException("Can't find the Core AAM instance");
        }

        Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            PrivateKey pvKey = (PrivateKey) trustStore.getKey(alias, keystorePassword.toCharArray());
            X509Certificate cert = (X509Certificate) trustStore.getCertificate(alias);

            String subject = cert.getSubjectX500Principal().getName();

            X500Name x500name = new JcaX509CertificateHolder(cert).getIssuer();
            RDN cn = x500name.getRDNs(BCStyle.CN)[0];
            String aamId = cn.getFirst().getValue().toString();


            if (subject.startsWith("CN=")) {
                String[] elements = subject.split("CN=")[1].split("@");
                if (elements.length > 1) {

                    String user;
                    String client;

                    if (elements.length > 2) {
                        user = elements[0];
                        client = elements[1];
                    } else {
                        user = elements[1];
                        client = elements[0];
                    }

                    AAM aam = aamList.get(aamId);

                    if (aam != null) {
                        Certificate certificate = new Certificate(CryptoHelper.convertX509ToPEM(cert));
                        BoundCredentials boundCredentials =
                                new BoundCredentials(new HomeCredentials(aam, user, client, certificate, pvKey));

                        credentialsWallet.put(aamId, boundCredentials);
                    }
                }
            }
        }
    }

    private void saveCertificate(HomeCredentials credentials) throws
            IOException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException {

        KeyStore trustStore = getKeystore();

        String aliastag = credentials.homeAAM.getAamInstanceId();

        trustStore.setKeyEntry(aliastag, credentials.privateKey, keystorePassword.toCharArray(),
                new java.security.cert.Certificate[]{credentials.certificate.getX509()});

        FileOutputStream fOut = new FileOutputStream(keystorePath);
        trustStore.store(fOut, keystorePassword.toCharArray());
        fOut.close();
    }

}
