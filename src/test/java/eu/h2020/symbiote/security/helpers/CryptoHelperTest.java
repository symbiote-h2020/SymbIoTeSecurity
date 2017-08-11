package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
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

import static eu.h2020.symbiote.security.helpers.CryptoHelper.convertPemToPKCS10CertificationRequest;
import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by Jakub on 20.07.2017.
 */

public class CryptoHelperTest {

    private final String username = "testusername";
    private final String clientId = "testclientid";
    private final String platformId = "platformid";
    private final String componentId = "componentid";
    private static final String CERTIFICATE_ALIAS = "core-2";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/platform_1.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";

    @Before
    public void setUp() throws Exception {
        ECDSAHelper.enableECDSAProvider();
    }

    @Test
    public void buildLoginRequestTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, JWTCreationException, MalformedJWTException, ValidationException, CertificateException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, keyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        JWTClaims claims = JWTEngine.getClaimsFromToken(loginRequest);
        assertEquals(homeCredentials.username, claims.getIss());
        assertEquals(homeCredentials.clientIdentifier, claims.getSub());
        assertEquals(ValidationStatus.VALID, JWTEngine.validateTokenString(loginRequest, keyPair.getPublic()));
    }

    @Test
    public void buildCertificateSigningRequestTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, CertificateException, OperatorCreationException, PKCSException, SignatureException, InvalidKeyException, InvalidArgumentsException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(CERTIFICATE_ALIAS);
        String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificate, username, clientId, keyPair);
        PKCS10CertificationRequest pkcsCSR = convertPemToPKCS10CertificationRequest(csr);
        assertEquals(username + illegalSign + clientId + illegalSign + certificate.getSubjectX500Principal().getName().split("CN=")[1].split(",")[0], pkcsCSR.getSubject().toString().split("CN=")[1]);
        assertTrue(pkcsCSR.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(keyPair.getPublic())));
    }

    @Test
    public void buildPlatformCertificateSigningRequestTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, CertificateException, OperatorCreationException, PKCSException, SignatureException, InvalidKeyException, InvalidArgumentsException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        //KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        //ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        //X509Certificate certificate = (X509Certificate) ks.getCertificate(CERTIFICATE_ALIAS);
        String csr = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, keyPair);
        PKCS10CertificationRequest pkcsCSR = convertPemToPKCS10CertificationRequest(csr);
        assertEquals(platformId, pkcsCSR.getSubject().toString().split("CN=")[1]);
        assertTrue(pkcsCSR.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(keyPair.getPublic())));
    }

    @Test
    public void buildComponentCertificateSigningRequestTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, CertificateException, OperatorCreationException, PKCSException, SignatureException, InvalidKeyException, InvalidArgumentsException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        //KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        //ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        //X509Certificate certificate = (X509Certificate) ks.getCertificate(CERTIFICATE_ALIAS);
        String csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, keyPair);
        PKCS10CertificationRequest pkcsCSR = convertPemToPKCS10CertificationRequest(csr);
        assertEquals(componentId + illegalSign + platformId, pkcsCSR.getSubject().toString().split("CN=")[1]);
        assertTrue(pkcsCSR.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(keyPair.getPublic())));
    }


}