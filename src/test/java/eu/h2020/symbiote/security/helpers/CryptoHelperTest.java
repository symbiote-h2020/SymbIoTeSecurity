package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.FIELDS_DELIMITER;
import static eu.h2020.symbiote.security.helpers.CryptoHelper.convertPemToPKCS10CertificationRequest;
import static org.junit.Assert.*;

/**
 * Created by Jakub on 20.07.2017.
 */

public class CryptoHelperTest {

    private static final String CERTIFICATE_ALIAS = "core-2";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/platform_1.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private final String username = "testusername";
    private final String clientId = "testclientid";
    private final String platformId = "platformid";
    private final String componentId = "componentid";

    // Leaf Certificate
    private static String applicationCertificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIBijCCAS+gAwIBAgIEWZWcVTAKBggqhkjOPQQDAjB0MRQwEgYJKoZIhvcNAQkB\n" +
                    "FgVhQGIuYzENMAsGA1UECxMEdGVzdDENMAsGA1UEChMEdGVzdDENMAsGA1UEBxME\n" +
                    "dGVzdDENMAsGA1UECBMEdGVzdDELMAkGA1UEBhMCUEwxEzARBgNVBAMTCnBsYXRm\n" +
                    "b3JtLTEwHhcNMTcwODE3MTMzOTQ2WhcNMjIwODE3MTMzOTQ2WjAlMSMwIQYDVQQD\n" +
                    "DBp1c2VySWRAY2xpZW50SWRAcGxhdGZvcm0tMTBZMBMGByqGSM49AgEGCCqGSM49\n" +
                    "AwEHA0IABFIfctCqbX0g6Mh1kmsl00zshX1W1rVQH9q6JkpwQUOODRImpErxSPW/\n" +
                    "0GvgdMIe2RVDqKsssdFhfBYQsK/Nj9gwCgYIKoZIzj0EAwIDSQAwRgIhALUpy+Pi\n" +
                    "yyDIj6yRVG4vSng4RfkzFPFJpY1jecQjHBkQAiEAhtZ2kkMlPUE6VCQFb7yaHP9I\n" +
                    "r2FAeAnhxNTUnAR+7Yg=\n" +
                    "-----END CERTIFICATE-----\n";
    //  Intermediate Certificate (the good one)
    private static String rightSigningAAMCertificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIICBzCCAaqgAwIBAgIEW/ehcjAMBggqhkjOPQQDAgUAMEkxDTALBgNVBAcTBHRl\n" +
                    "c3QxDTALBgNVBAoTBHRlc3QxDTALBgNVBAsTBHRlc3QxGjAYBgNVBAMMEVN5bWJJ\n" +
                    "b1RlX0NvcmVfQUFNMB4XDTE3MDYxMzEwMjkxOVoXDTI3MDYxMTEwMjkxOVowdDEU\n" +
                    "MBIGCSqGSIb3DQEJARYFYUBiLmMxDTALBgNVBAsTBHRlc3QxDTALBgNVBAoTBHRl\n" +
                    "c3QxDTALBgNVBAcTBHRlc3QxDTALBgNVBAgTBHRlc3QxCzAJBgNVBAYTAlBMMRMw\n" +
                    "EQYDVQQDEwpwbGF0Zm9ybS0xMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7eSa\n" +
                    "IbqcQJsiQdfEzOZFnfUPejSJJCoTxI+vafbKWrrVRQSdKw0vV/Rddgu5IxVNqdWK\n" +
                    "lkwirWlMZXLRGqfwh6NTMFEwHwYDVR0jBBgwFoAUNiFCbRtr/vdc4oaiASrBxosU\n" +
                    "uZQwDwYDVR0TBAgwBgEB/wIBADAdBgNVHQ4EFgQUdxSdPTW56zEh0Wuqfx26J4ve\n" +
                    "QWwwDAYIKoZIzj0EAwIFAANJADBGAiEAv/MmIW8g5I6dVOjoRins750rxnt9OcpP\n" +
                    "VvOHShi5YqYCIQDRvpwyWySQ0U0LKjzob/GwqeYJ+6el8x1xbpJhs0Uweg==\n" +
                    "-----END CERTIFICATE-----\n";
    private static String rightCoreAAMCertificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIBuTCCAV6gAwIBAgIEAzXi2DAMBggqhkjOPQQDAgUAMEkxDTALBgNVBAcTBHRl\n" +
                    "c3QxDTALBgNVBAoTBHRlc3QxDTALBgNVBAsTBHRlc3QxGjAYBgNVBAMMEVN5bWJJ\n" +
                    "b1RlX0NvcmVfQUFNMB4XDTE3MDYxMzA4NTU1MloXDTI3MDYxMTA4NTU1MlowSTEN\n" +
                    "MAsGA1UEBxMEdGVzdDENMAsGA1UEChMEdGVzdDENMAsGA1UECxMEdGVzdDEaMBgG\n" +
                    "A1UEAwwRU3ltYklvVGVfQ29yZV9BQU0wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n" +
                    "AAQ9p4MLgiA64c099f5MOdm6+cvBOWzTQM+ijGJUEs7eSvjsLAypcmfbvKK1ZhEN\n" +
                    "D7R9ee/fUeVsqctFkqMlrJLPozIwMDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW\n" +
                    "BBQ2IUJtG2v+91zihqIBKsHGixS5lDAMBggqhkjOPQQDAgUAA0cAMEQCIH/6EiOI\n" +
                    "ve5uN+hnCgq836bMBAMDkLrLcDfEWgqbxApnAiAcwzxT2A5rzbIOmpuq1w7VNYcc\n" +
                    "v9tugm8GgbBo0Edfjw==\n" +
                    "-----END CERTIFICATE-----\n";
    //  Intermediate Certificate (the bad one)
    private static String wrongSigningAAMCertificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIBrTCCAVOgAwIBAgIEWT/PizAKBggqhkjOPQQDAjBJMQ0wCwYDVQQHEwR0ZXN0\n" +
                    "MQ0wCwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MRowGAYDVQQDDBFTeW1iSW9U\n" +
                    "ZV9Db3JlX0FBTTAeFw0xNzA2MTMxMTQyMjVaFw0yNzA2MTMxMTQyMjVaMHQxFDAS\n" +
                    "BgkqhkiG9w0BCQEWBWFAYi5jMQ0wCwYDVQQLEwR0ZXN0MQ0wCwYDVQQKEwR0ZXN0\n" +
                    "MQ0wCwYDVQQHEwR0ZXN0MQ0wCwYDVQQIEwR0ZXN0MQswCQYDVQQGEwJQTDETMBEG\n" +
                    "A1UEAxMKcGxhdGZvcm0tMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMaODIy1\n" +
                    "sOOJdmd7stBIja4eGn9eKUEU/LVwocfiu6EW1pnZraI1Uqpu7t9CNjsFxWi/jDVg\n" +
                    "kViBAy/bg9kzocMwCgYIKoZIzj0EAwIDSAAwRQIhAIBz2MJoERVLmYxs7P0B5dCn\n" +
                    "yqWmjrYhosEiCUoVxIQVAiAwhZdM0XAeGGfTP2WsXGKFtcw/nL/gzvYSjAAGbkyx\n" +
                    "sw==\n" +
                    "-----END CERTIFICATE-----\n";

    @Before
    public void setUp() {
        ECDSAHelper.enableECDSAProvider();
    }

    @Test
    public void buildLoginRequestTest() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            MalformedJWTException,
            ValidationException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, keyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        JWTClaims claims = JWTEngine.getClaimsFromToken(loginRequest);
        assertEquals(homeCredentials.username, claims.getIss());
        assertEquals(homeCredentials.clientIdentifier, claims.getSub());
        assertEquals(ValidationStatus.VALID, JWTEngine.validateTokenString(loginRequest, keyPair.getPublic()));
    }

    @Test
    public void buildCertificateSigningRequestTest() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            OperatorCreationException,
            PKCSException,
            InvalidArgumentsException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(CERTIFICATE_ALIAS);
        String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificate, username, clientId, keyPair);
        PKCS10CertificationRequest pkcsCSR = convertPemToPKCS10CertificationRequest(csr);
        assertEquals(username + FIELDS_DELIMITER + clientId + FIELDS_DELIMITER + certificate.getSubjectX500Principal().getName().split("CN=")[1].split(",")[0], pkcsCSR.getSubject().toString().split("CN=")[1]);
        assertTrue(pkcsCSR.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(keyPair.getPublic())));
    }

    @Test
    public void buildPlatformCertificateSigningRequestTest() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            OperatorCreationException,
            PKCSException,
            InvalidArgumentsException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        //KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        //ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        //X509Certificate certificate = (X509Certificate) ks.getAamCACertificate(CERTIFICATE_ALIAS);
        String csr = CryptoHelper.buildServiceCertificateSigningRequestPEM(platformId, keyPair);
        PKCS10CertificationRequest pkcsCSR = convertPemToPKCS10CertificationRequest(csr);
        assertEquals(platformId, pkcsCSR.getSubject().toString().split("CN=")[1]);
        assertTrue(pkcsCSR.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(keyPair.getPublic())));
    }

    @Test
    public void buildComponentCertificateSigningRequestTest() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            OperatorCreationException,
            PKCSException,
            InvalidArgumentsException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        //KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        //ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        //X509Certificate certificate = (X509Certificate) ks.getAamCACertificate(CERTIFICATE_ALIAS);
        String csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, keyPair);
        PKCS10CertificationRequest pkcsCSR = convertPemToPKCS10CertificationRequest(csr);
        assertEquals(componentId + FIELDS_DELIMITER + platformId, pkcsCSR.getSubject().toString().split("CN=")[1]);
        assertTrue(pkcsCSR.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(keyPair.getPublic())));
    }

    @Test
    public void validateCertificateChainClientSuccess() throws
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException {
        assertTrue(CryptoHelper.isClientCertificateChainTrusted(rightCoreAAMCertificatePEM, rightSigningAAMCertificatePEM, applicationCertificatePEM));
    }

    @Test
    public void validateCertificateChainCoreComponentSuccess() throws
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException {
        assertTrue(CryptoHelper.isClientCertificateChainTrusted(rightSigningAAMCertificatePEM, rightSigningAAMCertificatePEM, applicationCertificatePEM));
    }

    @Test
    public void validateCertificateChainFailure() throws
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException {
        assertFalse(CryptoHelper.isClientCertificateChainTrusted(wrongSigningAAMCertificatePEM, wrongSigningAAMCertificatePEM, applicationCertificatePEM));
    }

}