package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.SecurityCredentials;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.utils.DummyTokenIssuer;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper.hashSHA256;
import static org.junit.Assert.*;

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
    private Token guestToken;

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

        this.guestToken = new Token(DummyTokenIssuer.buildAuthorizationToken(clientId,
                null,
                clientPublicKey.getEncoded(),
                Token.Type.GUEST,
                (long) (36000000),
                "",
                issuingAAMPublicKey,
                issuingAAMPrivateKey));

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

    @Test
    public void isSecurityRequestVerifiedFailsWrongAuthenticationChallenge() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            UnrecoverableKeyException,
            ValidationException,
            MalformedJWTException,
            InvalidKeySpecException, InterruptedException {

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
        AAM issuingAAM = new AAM("", "", "", new Certificate(CryptoHelper.convertX509ToPEM(issuingAAMCertificate)));
        HomeCredentials homeCredentials = new HomeCredentials(issuingAAM, username, clientId, new Certificate(CryptoHelper.convertX509ToPEM(clientCertificate)), clientPrivateKey);

        String authorizationToken = DummyTokenIssuer.buildAuthorizationToken(clientId,
                null,
                clientPublicKey.getEncoded(),
                Token.Type.HOME,
                (long) (3600000),
                "",
                issuingAAMPublicKey,
                issuingAAMPrivateKey);
        Token authToken = new Token(authorizationToken);
        String hexHash = hashSHA256("wrongHash");

        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setId(authToken.getClaims().getId()); // jti
        jwtBuilder.setIssuer(authToken.getClaims().getIssuer()); // iss
        jwtBuilder.claim("ipk", authToken.getClaims().get("spk"));
        jwtBuilder.claim("hash", hexHash);
        jwtBuilder.signWith(SignatureAlgorithm.ES256, homeCredentials.privateKey);
        String authenticationChallenge = jwtBuilder.compact();
        String clientCertificateString = homeCredentials.certificate.getCertificateString();
        String signingAAMCertificate = homeCredentials.homeAAM.getCertificate().getCertificateString();

        Set<SecurityCredentials> securityCredentialsSet = new HashSet<>();
        securityCredentialsSet.add(new SecurityCredentials(authToken.toString(), Optional.of(authenticationChallenge), Optional.of(clientCertificateString), Optional.of(signingAAMCertificate)));

        SecurityRequest securityRequest = new SecurityRequest(securityCredentialsSet, (long) 12);
        assertFalse(MutualAuthenticationHelper.isSecurityRequestVerified(securityRequest));
    }

    @Test
    public void isSecurityRequestVerifiedFailsOldToken() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            UnrecoverableKeyException,
            ValidationException,
            MalformedJWTException,
            InvalidKeySpecException, InterruptedException {

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
        AAM issuingAAM = new AAM("", "", "", new Certificate(CryptoHelper.convertX509ToPEM(issuingAAMCertificate)));
        HomeCredentials homeCredentials = new HomeCredentials(issuingAAM, username, clientId, new Certificate(CryptoHelper.convertX509ToPEM(clientCertificate)), clientPrivateKey);

        KeyPair a = CryptoHelper.createKeyPair();

        String wrongAuthorizationToken = DummyTokenIssuer.buildAuthorizationToken(clientId,
                null,
                clientPublicKey.getEncoded(),
                Token.Type.HOME,
                (long) (5000),
                "",
                issuingAAMPublicKey,
                issuingAAMPrivateKey);

        AuthorizationCredentials authorizationCredentials = new AuthorizationCredentials(new Token(wrongAuthorizationToken), homeCredentials);
        Set<AuthorizationCredentials> wrongAuthorizationCredentialsSet = new HashSet<>();
        wrongAuthorizationCredentialsSet.add(authorizationCredentials);
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(wrongAuthorizationCredentialsSet, true);
        Thread.sleep(5000);
        assertFalse(MutualAuthenticationHelper.isSecurityRequestVerified(securityRequest));
    }

    @Test
    public void getSecurityRequestForGuestSuccess() throws MalformedJWTException, ValidationException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        try {

            SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.guestToken);
            assertEquals(this.guestToken.toString(), securityRequest.getSecurityCredentials().iterator().next().getToken());

        } catch (Exception e) {
            log.info(e.getMessage());
            throw e;
        }
    }

    @Test
    public void isSecurityRequestForGuestVerifiedSuccess() throws MalformedJWTException, ValidationException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        try {

            SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.guestToken);
            assertEquals(this.guestToken.toString(), securityRequest.getSecurityCredentials().iterator().next().getToken());
            assertTrue(MutualAuthenticationHelper.isSecurityRequestVerified(securityRequest));

        } catch (Exception e) {
            log.info(e.getMessage());
            throw e;
        }
    }

}
