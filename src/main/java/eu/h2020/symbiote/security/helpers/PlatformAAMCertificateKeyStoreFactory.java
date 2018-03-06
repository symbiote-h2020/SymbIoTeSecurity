package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Properties;

/**
 * Builds a key store with platform certificate and it's issuer
 *
 * @author Jakub Toczek (PSNC)
 */
public class PlatformAAMCertificateKeyStoreFactory extends AbstractAAMCertificateKeyStoreFactory {

    private static Log log = LogFactory.getLog(PlatformAAMCertificateKeyStoreFactory.class);

    /**
     * Generates a platform AAM keystore.
     * <p>
     * Fill properly all the fields in as in the template 'cert.properties' to get the platform AAM keystore.
     * You can send as first argument the name of the file if it is nod default name. If you do not provide default
     * filename the it uses 'cert.properties'.
     * <p>
     * You need to build all jar with gradle task: buildRunnablePAAMKeystoreFactoryJAR
     * <p>
     * After that you can start it e.g., java -jar build/libs/SymbIoTeSecurity-all-23.0.2.jar
     */
    public static void main(String[] args) {
        Properties props = new Properties();
        argumentsCheck(args, props);

        // given to you for integration, in the end should be available in public
        // from spring bootstrap file: symbIoTe.core.interface.url
        String coreAAMAddress = (String) props.computeIfAbsent("coreAAMAddress",
                (p) -> exit("Property 'coreAAMAddress' can not be absent."));
        // of the user registered through administration in the symbIoTe Core
        String platformOwnerUsername = (String) props.computeIfAbsent("platformOwnerUsername",
                (p) -> exit("Property 'platformOwnerUsername' can not be absent."));
        String platformOwnerPassword = (String) props.computeIfAbsent("platformOwnerPassword",
                (p) -> exit("Property 'platformOwnerPassword' can not be absent."));
        // of the platform registered to the given platform Owner
        String platformId = (String) props.computeIfAbsent("platformId",
                (p) -> exit("Property 'platformId' can not be absent."));

        // how the generated keystore should be named
        String keyStoreFileName = (String) props.computeIfAbsent("keyStoreFileName",
                (p) -> exit("Property keyStoreFileName anc not be absent."));
        // used to access the keystore. MUST NOT be longer than 7 chars
        // from spring bootstrap file: aam.security.KEY_STORE_PASSWORD
        // R3 dirty fix MUST BE THE SAME as spring bootstrap file: aam.security.PV_KEY_PASSWORD
        String keyStorePassword = props.getProperty("keyStorePassword", "pass");
        // platform AAM key/certificate alias... case INSENSITIVE (all lowercase)
        // from spring bootstrap file: aam.security.CERTIFICATE_ALIAS
        String aamCertificateAlias = props.getProperty("aamCertificateAlias", "paam");
        // root CA certificate alias... case INSENSITIVE (all lowercase)
        // from spring bootstrap file:  aam.security.ROOT_CA_CERTIFICATE_ALIAS
        String rootCACertificateAlias = props.getProperty("rootCACertificateAlias", "caam");

        try {
            getServiceAAMKeystore(
                    coreAAMAddress,
                    platformOwnerUsername,
                    platformOwnerPassword,
                    platformId,
                    keyStoreFileName,
                    keyStorePassword,
                    rootCACertificateAlias,
                    aamCertificateAlias,
                    log
            );
            log.info("OK");
        } catch (SecurityException
                | IOException
                | CertificateException
                | InvalidAlgorithmParameterException
                | NoSuchAlgorithmException
                | KeyStoreException
                | NoSuchProviderException e) {
            log.error(e);
        }
    }


}
