package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Properties;

/**
 * Builds a key store with smart space certificate and it's issuer
 *
 * @author Jakub Toczek (PSNC)
 */
public class SmartSpaceAAMCertificateKeyStoreFactory {

    private static Log log = LogFactory.getLog(SmartSpaceAAMCertificateKeyStoreFactory.class);

    /**
     * Generates a smart space AAM keystore.
     * <p>
     * Fill properly all the fields in as in the template 'cert.properties' to get the smart space AAM keystore.
     * You can send as first argument the name of the file if it is nod default name. If you do not provide default
     * filename the it uses 'cert.properties'.
     * <p>
     * You need to build all jar with gradle task: buildRunnableSAAMKeystoreFactoryJAR
     * <p>
     * After that you can start it e.g., java -jar build/libs/SymbIoTeSecurity-all-24.1.0.jar
     */
    public static void main(String[] args) {
        Properties props = new Properties();
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

        // given to you for integration, in the end should be available in public
        // from spring bootstrap file: symbIoTe.core.interface.url
        String coreAAMAddress = (String) props.computeIfAbsent("coreAAMAddress",
                (p) -> exit("Property 'coreAAMAddress' can not be absent."));
        // of the user registered through administration in the symbIoTe Core
        String smartSpaceOwnerUsername = (String) props.computeIfAbsent("smartSpaceOwnerUsername",
                (p) -> exit("Property 'smartSpaceOwnerUsername' can not be absent."));
        String smartSpaceOwnerPassword = (String) props.computeIfAbsent("smartSpaceOwnerPassword",
                (p) -> exit("Property 'smartSpaceOwnerPassword' can not be absent."));
        // of the smart space registered to the given smart space Owner
        String smartSpaceId = (String) props.computeIfAbsent("smartSpaceId",
                (p) -> exit("Property 'smartSpaceId' can not be absent."));

        // how the generated keystore should be named
        String keyStoreFileName = (String) props.computeIfAbsent("keyStoreFileName",
                (p) -> exit("Property keyStoreFileName anc not be absent."));
        // used to access the keystore. MUST NOT be longer than 7 chars
        // from spring bootstrap file: aam.security.KEY_STORE_PASSWORD
        // R3 dirty fix MUST BE THE SAME as spring bootstrap file: aam.security.PV_KEY_PASSWORD
        String keyStorePassword = props.getProperty("keyStorePassword", "pass");
        // smartSpace AAM key/certificate alias... case INSENSITIVE (all lowercase)
        // from spring bootstrap file: aam.security.CERTIFICATE_ALIAS
        String aamCertificateAlias = props.getProperty("aamCertificateAlias", "saam");
        // root CA certificate alias... case INSENSITIVE (all lowercase)
        // from spring bootstrap file:  aam.security.ROOT_CA_CERTIFICATE_ALIAS
        String rootCACertificateAlias = props.getProperty("rootCACertificateAlias", "caam");

        try {
            PlatformAAMCertificateKeyStoreFactory.getPlatformAAMKeystore(
                    coreAAMAddress,
                    smartSpaceOwnerUsername,
                    smartSpaceOwnerPassword,
                    smartSpaceId,
                    keyStoreFileName,
                    keyStorePassword,
                    rootCACertificateAlias,
                    aamCertificateAlias
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

    private static String exit(String msg) {
        System.err.println(msg);
        System.exit(3);
        return null;
    }


}
