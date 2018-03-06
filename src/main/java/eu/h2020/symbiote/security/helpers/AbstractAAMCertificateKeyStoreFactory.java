package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import org.apache.commons.logging.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Properties;

abstract class AbstractAAMCertificateKeyStoreFactory {

    public static void getServiceAAMKeystore(String coreAAMAddress,
                                             String serviceOwnerUsername,
                                             String serviceOwnerPassword,
                                             String serviceId,
                                             String keyStoreFileName,
                                             String keyStorePassword,
                                             String rootCACertificateAlias,
                                             String aamCertificateAlias,
                                             Log log
    ) throws
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            InvalidArgumentsException,
            NotExistingUserException,
            ValidationException,
            AAMException {

        if (!keyStoreFileName.endsWith(".p12")) {
            keyStoreFileName = keyStoreFileName + ".p12";
        }
        File keyStoreFile = new File(keyStoreFileName);

        if (keyStorePassword.length() > 7)
            throw new InvalidArgumentsException("The passwords must not be longer that 7 chars... don't ask why...");

        ECDSAHelper.enableECDSAProvider();
        KeyStore ks = getKeystore(keyStoreFileName, keyStorePassword, log);
        log.info("Key Store generated.");
        KeyPair pair = CryptoHelper.createKeyPair();
        log.info("Key pair for the service's AAM generated.");
        String csr = CryptoHelper.buildServiceCertificateSigningRequestPEM(serviceId, pair);
        log.info("CSR for the service's AAM generated.");
        CertificateRequest request = new CertificateRequest(serviceOwnerUsername, serviceOwnerPassword, serviceId, csr);
        log.info("Request created");
        AAMClient aamClient = new AAMClient(coreAAMAddress);
        log.info("Connection with AAMClient established");
        String serviceAAMCertificate = aamClient.signCertificateRequest(request);
        log.info("Service Certificate acquired");
        if (!aamClient.getComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME, serviceId).equals(serviceAAMCertificate)) {
            throw new CertificateException("Wrong certificate under the platform / smart space Id");
        }
        // rootCA part
        Certificate rootAAMCertificate = aamClient.getAvailableAAMs().getAvailableAAMs().get(SecurityConstants.CORE_AAM_INSTANCE_ID).getAamCACertificate();
        ks.setCertificateEntry(rootCACertificateAlias, rootAAMCertificate.getX509());

        /*
        // TODO fix in R5
        KeyStore.ProtectionParameter protParam =
                new KeyStore.PasswordProtection(privateKeyPassword.toCharArray());

        // prepare private key entry
        //
        KeyStore.PrivateKeyEntry pkEntry = new KeyStore.PrivateKeyEntry(pair.getPrivate(),
                new java.security.cert.Certificate[]{
                        CryptoHelper.convertPEMToX509(platformAAMCertificate),
                        rootAAMCertificate.getX509()});

        // save my secret key
        ks.setEntry(aamCertificateAlias, pkEntry, protParam);
        */

        ks.setKeyEntry(aamCertificateAlias, pair.getPrivate(), keyStorePassword.toCharArray(),
                new java.security.cert.Certificate[]{CryptoHelper.convertPEMToX509(serviceAAMCertificate), rootAAMCertificate.getX509()});
        FileOutputStream fOut = new FileOutputStream(keyStoreFile);
        try {
            ks.store(fOut, keyStorePassword.toCharArray());
        } catch (Exception e) {
            log.error(e);
            try {
                fOut.close();
                keyStoreFile.delete();
            } catch (IOException ioe) {
                // Do nothing. We're doomed.
            }
            throw e;
        }
        fOut.close();
        log.info("Certificates and private key saved in keystore");
    }

    private static KeyStore getKeystore(String path, String password, Log log) throws
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException {
        ECDSAHelper.enableECDSAProvider();
        KeyStore trustStore = KeyStore.getInstance("PKCS12", "BC");
        File f = new File(path);
        if (f.exists() && !f.isDirectory()) {
            log.warn("KeyStore already exists. It was overridden");
            f.delete();
        }
        trustStore.load(null, password.toCharArray());
        return trustStore;
    }

    static String exit(String msg) {
        System.err.println(msg);
        System.exit(3);
        return null;
    }

    protected static void argumentsCheck(String[] args, Properties props) {
        if (args.length == 1) {
            try {
                props.load(new FileReader(args[0]));
            } catch (IOException e) {
                System.err.println("Can not load properties file '" + args[0] + "'. Reason: " + e);
                System.exit(1);
            }
        } else {
            try {
                props.load(new FileReader("cert.properties"));
            } catch (IOException e) {
                System.err.println("Can not load properties file 'cert.properties'. Reason: " + e);
                System.exit(2);
            }
        }
    }
}
