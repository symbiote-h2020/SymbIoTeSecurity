package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import org.junit.Before;
import org.junit.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertEquals;

/**
 * Created by Jakub on 20.07.2017.
 */

public class CryptoHelperTest {

    private final String username = "testusername";
    private final String clientId = "testclientid";

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
}