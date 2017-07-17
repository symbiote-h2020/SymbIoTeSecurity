package eu.h2020.symbiote.security.communication.clients.rest.clients;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.communication.clients.rest.AAMRESTInterface;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.handler.SecurityHandler;
import feign.Feign;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Client for Symbiote's AAMs' services.
 * <p>
 * To learn about available entry points fetch them using {@link SecurityHandler#getAvailableAAMs()}
 *
 * @author Elena Garrido (Atos)
 * @author Mikołaj Dobski (PSNC)
 */
public class AAMClient {

    private static final Log logger = LogFactory.getLog(AAMClient.class);
    private static final String errorMessage = "Error accessing to AAM server at ";
    private AAMRESTInterface simpleclient;
    private AAMRESTInterface jsonclient;
    private String url;

    /**
     * For the use of specific implementations
     */
    protected AAMClient() {
    }

    /**
     * Used to create the symbiote entry point to selected AAMs
     *
     * @param aam to learn about available platform AAMs fetch them using {@link SecurityHandler#getAvailableAAMs()} from the Core AAM
     */
    public AAMClient(AAM aam) {
        this.createClient(aam.getAamAddress());
    }

    protected void createClient(String url) {
        this.url = url;
        simpleclient = Feign.builder().target(AAMRESTInterface.class, url);
        jsonclient = Feign.builder().decoder(new JacksonDecoder()).encoder(new JacksonEncoder()).target
                (AAMRESTInterface.class, url);
    }

    public String getURL() {
        return url;
    }

    private String getAAMCertificatePEMString() {
        String result = null;
        try {
            result = simpleclient.getRootCertificate();
        } catch (Exception e) {
            logger.error(errorMessage + url, e);
        }
        return result;
    }

    public X509Certificate getAAMCertificate() throws CertificateException {
        String pemCert = getAAMCertificatePEMString();
        if (pemCert == null || pemCert.isEmpty())
            return null;
        return new Certificate(pemCert).getX509();
    }

    public Token login(Credentials credential) {
        Token result = null;
        try {
            logger.info("User trying to login " + credential.getUsername() + " - " + credential.getPassword());
            result = new Token(jsonclient.login(credential).headers().get(SecurityConstants.TOKEN_HEADER_NAME)
                    .iterator()
                    .next());
        } catch (Exception e) {
            logger.error(errorMessage + url, e);
        }
        return result;
    }

    public ValidationStatus validate(Token token) {
        ValidationStatus result = null;
        try {
            logger.info("User trying to validate");
            result = jsonclient.validate(token.getToken());
        } catch (Exception e) {
            logger.error(errorMessage + url, e);
        }
        return result;
    }

    public Token requestFederatedToken(Token token) {
        Token result = null;
        try {
            logger.info("User trying to requestFederatedToken");
            result = new Token(jsonclient.requestForeignToken(token.getToken()).headers().get(SecurityConstants
                    .TOKEN_HEADER_NAME).iterator().next());
        } catch (Exception e) {
            logger.error(errorMessage + url, e);
        }
        return result;
    }

}

