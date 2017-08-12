package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.utils.DummyTokenIssuer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;

import static org.junit.Assert.assertTrue;

/**
 * Provides tests for MutualAuthenticationHelper class methods
 * <p>
 *
 * @author Daniele Caldarola (CNIT)
 */
public class MutualAuthenticationHelperTest {

    private static Log log = LogFactory.getLog(MutualAuthenticationHelperTest.class);

    private final String username = "testusername";
    private final String clientId = "testclientid";
    private static final String ISSUING_AAM_CERTIFICATE_ALIAS = "core-1";
    private static final String CLIENT_CERTIFICATE_ALIAS = "client-core-1";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/core.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private static final String SERVICE_CERTIFICATE_ALIAS = "platform-1-1-c1"; // let's suppose it
    private static final String SERVICE_CERTIFICATE_LOCATION = "./src/test/resources/platform_1.p12"; // let's suppose it
    private HashSet<AuthorizationCredentials> authorizationCredentialsSet = new HashSet<AuthorizationCredentials>();

    @Before
    public void setUp() throws Exception {
        ECDSAHelper.enableECDSAProvider();

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());

        // issuing AAM platform (core-1 in this case)
        X509Certificate issuingAAMCertificate = (X509Certificate) ks.getCertificate(ISSUING_AAM_CERTIFICATE_ALIAS);
        PublicKey issuingAAMPublicKey = issuingAAMCertificate.getPublicKey();
        PrivateKey issuingAAMPrivateKey = (PrivateKey) ks.getKey(ISSUING_AAM_CERTIFICATE_ALIAS, CERTIFICATE_PASSWORD.toCharArray());

        // client
        X509Certificate clientCertificate = (X509Certificate) ks.getCertificate(CLIENT_CERTIFICATE_ALIAS);
        PublicKey clientPublicKey = clientCertificate.getPublicKey();
        PrivateKey clientPrivateKey = (PrivateKey) ks.getKey(CLIENT_CERTIFICATE_ALIAS, CERTIFICATE_PASSWORD.toCharArray());

        // client home credentials
        AAM issuingAAM = new AAM("","","", new Certificate(CryptoHelper.convertX509ToPEM(issuingAAMCertificate)));
        HomeCredentials homeCredentials = new HomeCredentials(issuingAAM, username, clientId, new Certificate(CryptoHelper.convertX509ToPEM(clientCertificate)), clientPrivateKey);

        String authorizationToken = DummyTokenIssuer.buildAuthorizationToken(clientId,
                null,
                clientPublicKey.getEncoded(),
                Token.Type.HOME,
                (long) (36000000),
                "",
                issuingAAMPublicKey,
                issuingAAMPrivateKey);

        AuthorizationCredentials authorizationCredentials = new AuthorizationCredentials(new Token(authorizationToken), homeCredentials);
        this.authorizationCredentialsSet.add(authorizationCredentials);
    }

    @Test
    public void getSecurityRequestSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            UnrecoverableKeyException,
            ValidationException {

        try {
            SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(authorizationCredentialsSet, false);
            SecurityRequest securityRequestCertsAttached = MutualAuthenticationHelper.getSecurityRequest(authorizationCredentialsSet, true);
        } catch(Exception e) {
            log.info(e.getMessage());
            throw e;
        }
    }

    @Test
    public void isSecurityRequestVerifiedSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            UnrecoverableKeyException,
            ValidationException,
            MalformedJWTException,
            InvalidKeySpecException {

        SecurityRequest securityRequestCertsAttached = MutualAuthenticationHelper.getSecurityRequest(authorizationCredentialsSet, true);

        assertTrue(MutualAuthenticationHelper.isSecurityRequestVerified(securityRequestCertsAttached));
    }

    @Test
    public void getServiceResponseSuccess() throws
            NoSuchAlgorithmException,
            UnrecoverableKeyException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(new FileInputStream(SERVICE_CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
            PrivateKey servicePrivateKey = (PrivateKey) ks.getKey(SERVICE_CERTIFICATE_ALIAS, CERTIFICATE_PASSWORD.toCharArray());
            SecurityRequest securityRequestCertsAttached = MutualAuthenticationHelper.getSecurityRequest(authorizationCredentialsSet, true);

            MutualAuthenticationHelper.getServiceResponse(servicePrivateKey, securityRequestCertsAttached.getTimestamp());

        } catch(Exception e) {
            log.info(e.getMessage());
            throw e;
        }
    }

    @Test
    public void isServiceResponseVerifiedSuccess() throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException {

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(SERVICE_CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate serviceCertificate = (X509Certificate) ks.getCertificate(SERVICE_CERTIFICATE_ALIAS);
        PrivateKey servicePrivateKey = (PrivateKey) ks.getKey(SERVICE_CERTIFICATE_ALIAS, CERTIFICATE_PASSWORD.toCharArray());
        SecurityRequest securityRequestCertsAttached = MutualAuthenticationHelper.getSecurityRequest(authorizationCredentialsSet, true);
        String serviceResponse = MutualAuthenticationHelper.getServiceResponse(servicePrivateKey,securityRequestCertsAttached.getTimestamp());

        assertTrue(MutualAuthenticationHelper.isServiceResponseVerified(serviceResponse, new Certificate(CryptoHelper.convertX509ToPEM(serviceCertificate))));
    }

}
