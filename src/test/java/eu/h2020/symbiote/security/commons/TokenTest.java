package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.handler.SecurityHandlerTest;
import eu.h2020.symbiote.security.utils.DummyTokenIssuer;
import org.junit.Test;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class TokenTest {


    @Test
    public void setTokenWithExpectedSignature() throws Throwable {
        Token token = new Token(getTokenString(DummyTokenIssuer.SignatureType.PROPER));
        assertNotNull(token);
    }

    @Test(expected = ValidationException.class)
    public void setTokenWithHackedSignature() throws Throwable {
        new Token(getTokenString(DummyTokenIssuer.SignatureType.ABUSING));
        fail();
    }


    @Test(expected = ValidationException.class)
    public void setTokenWithNoSignature() throws Throwable {
        new Token(getTokenString(DummyTokenIssuer.SignatureType.NONE));
        fail();
    }


    private String getTokenString(DummyTokenIssuer.SignatureType signatureType) throws
            Throwable {

        String result;
        String keystoreFilename = "./src/test/resources/core.p12";
        String spassword = "1234567";
        String alias = "client-core-1";

        char[] password = spassword.toCharArray();

        KeyStore keystore;
        java.security.cert.Certificate cert;
        String userId;
        HashMap<String, String> attributes;
        byte[] userPublicKey;
        Long tokenValidity;
        String deploymentID;
        PublicKey aamPublicKey;
        Key key;
        try (FileInputStream fIn = new FileInputStream(keystoreFilename)) {
            keystore = KeyStore.getInstance("JKS");

            //Leer
            keystore.load(fIn, password);
        }
        cert = keystore.getCertificate(alias);

        userId = "testClient";
        attributes = new HashMap<>();
        attributes.put("name", "testClient");

        userPublicKey = (cert.getPublicKey()).getEncoded();
        tokenValidity = SecurityHandlerTest.DateUtil.addDays(new Date(), 1).getTime();
        deploymentID = "testUser";
        aamPublicKey = cert.getPublicKey();

        key = keystore.getKey(alias, spassword.toCharArray());


        result = DummyTokenIssuer.buildAuthorizationToken(userId,
                attributes,
                userPublicKey,
                Token.Type.HOME,
                tokenValidity,
                deploymentID,
                aamPublicKey,
                (PrivateKey) key,
                signatureType);


        return result;
    }
}