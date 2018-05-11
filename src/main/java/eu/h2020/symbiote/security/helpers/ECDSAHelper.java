package eu.h2020.symbiote.security.helpers;

import java.security.Security;

/**
 * Utility class with methods making sure Elliptic Curve Digital Signature Algorithm works.
 * @author Mikołaj Dobski (PSNC)
 */
public class ECDSAHelper {

    /**
     * SymbIoTe requires Bouncy Castle Security provider to handle Elliptic Curve Digital Signature Algorithm in
     * Certificates
     */
    public static void enableECDSAProvider() {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
    }
}
