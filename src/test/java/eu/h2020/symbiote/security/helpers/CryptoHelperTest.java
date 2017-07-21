package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.Signature;
import java.security.SignedObject;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by Jakub on 20.07.2017.
 */

public class CryptoHelperTest {

    private final String testCryptoPayload = "testusername@testclientid";

    @Before
    public void setUp() throws Exception {
        ECDSAHelper.enableECDSAProvider();
    }

    @Test
    public void signedObjectToStringToSignedObject() throws Exception {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        SignedObject signedObject = CryptoHelper.objectToSignedObject(testCryptoPayload, keyPair.getPrivate());
        String stringObject = CryptoHelper.signedObjectToString(signedObject);

        SignedObject signedObjectBack = CryptoHelper.stringToSignedObject(stringObject);
        Signature signature = Signature.getInstance(SecurityConstants.SIGNATURE_ALGORITHM);
        assertEquals(testCryptoPayload, signedObjectBack.getObject().toString());
        assertTrue(CryptoHelper.verifySignedObject(signedObject, keyPair.getPublic()));
    }
}