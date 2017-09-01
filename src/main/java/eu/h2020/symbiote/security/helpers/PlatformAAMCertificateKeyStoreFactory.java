package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Builds a key store with platform certificate and it's issuer
 *
 * @author Jakub Toczek (PSNC)
 */
public class PlatformAAMCertificateKeyStoreFactory {

    private static Log log = LogFactory.getLog(PlatformAAMCertificateKeyStoreFactory.class);


    private PlatformAAMCertificateKeyStoreFactory() {
    }

    public static void main() throws WrongCredentialsException, ValidationException {

        // todo fill properly all the fields
        String keyStorePath = "";
        String keyStorePassword = "";
        String platformId = "";
        String platformOwnerUsername = "";
        String platformOwnerPassword = "";
        String clientId = "";
        String coreAAMAddress = "";
        String keyAlias = "";
        String coreCertificateAlias = "";

        try {
            getPlatformAAMKeystore(keyStorePath, keyStorePassword, platformId, platformOwnerUsername, platformOwnerPassword, clientId, coreAAMAddress, keyAlias, coreCertificateAlias);
            log.info("OK");
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | InvalidArgumentsException | InvalidAlgorithmParameterException | NoSuchProviderException | NotExistingUserException e) {
            log.error(e.getMessage());
            log.error(e.getCause());
        }
    }

    public static void getPlatformAAMKeystore(String keyStorePath, String keyStorePassword, String platformId, String platformOwnerUsername, String platformOwnerPassword, String clientId, String coreAAMAddress, String keyTag, String coreCertificateAlias) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidArgumentsException, WrongCredentialsException, NotExistingUserException, ValidationException {
        KeyStore ks = getKeystore(keyStorePath, keyStorePassword);
        log.info("Key Store acquired.");
        KeyPair pair = CryptoHelper.createKeyPair();
        log.info("Key pair for the platform AAM generated.");
        String csr = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        log.info("CSR for the platform AAM generated.");
        CertificateRequest request = new CertificateRequest();
        request.setUsername(platformOwnerUsername);
        request.setPassword(platformOwnerPassword);
        request.setClientId(clientId);
        request.setClientCSRinPEMFormat(csr);
        log.info("Request created");
        AAMClient aamClient = new AAMClient(coreAAMAddress);
        log.info("Connection with AAMClient established");
        String platformAAMCertificate = aamClient.getClientCertificate(request);
        log.info("Platform Certificate acquired");
        if (!aamClient.getAvailableAAMs().getAvailableAAMs().get(platformId).getAamCACertificate().getCertificateString().equals(platformAAMCertificate)) {
            throw new CertificateException("Wrong certificate under the platformId");
        }
        ks.setKeyEntry(keyTag, pair.getPrivate(), keyStorePassword.toCharArray(),
                new java.security.cert.Certificate[]{CryptoHelper.convertPEMToX509(platformAAMCertificate)});
        Certificate aamCertificate = aamClient.getAvailableAAMs().getAvailableAAMs().get(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID).getAamCACertificate();
        ks.setCertificateEntry(coreCertificateAlias, aamCertificate.getX509());
        FileOutputStream fOut = new FileOutputStream(keyStorePath);
        ks.store(fOut, keyStorePassword.toCharArray());
        fOut.close();
        log.info("Certificates and private key saved in keystore");
    }

    private static KeyStore getKeystore(String path, String password) throws
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        File f = new File(path);
        if (f.exists() && !f.isDirectory()) {
            log.warn("KeyStore already exists. It will be override");
            try (FileInputStream fIn = new FileInputStream(path)) {
                trustStore.load(fIn, password.toCharArray());
                fIn.close();
            }
        } else {
            trustStore.load(null, null);
        }
        return trustStore;
    }
}
