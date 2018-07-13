package eu.h2020.symbiote.security.helpers;

import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;

public class SDevHelperTest {
    private static final String STRING_TO_HASH = "testStringToHashWithNumbers1234";
    private static final String HASHED_STRING = "a38076890bdbb7e2142fd40c1a75b585ec21280a";

    @Test
    public void hashSHA1Test() throws NoSuchAlgorithmException {
        assertEquals(HASHED_STRING, SDevHelper.hashSHA1(STRING_TO_HASH));
    }
}
