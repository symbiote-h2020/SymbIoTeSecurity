package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/**
 * Utility class containing helper methods for PKI related operation (keys, certifates, conversions)
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class CryptoHelper {
    // Provider is used from the implementation
    public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

    public static KeyPair createKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(SecurityConstants.CURVE_NAME);
        KeyPairGenerator g = KeyPairGenerator.getInstance(SecurityConstants.KEY_PAIR_GEN_ALGORITHM, BouncyCastleProvider
                .PROVIDER_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        return g.generateKeyPair();
    }

    /**
     * @param homeCredentials users credentials
     * @return String loginRequest
     * @throws SecurityException error during creation of loginRequest
     */
    public static String buildHomeTokenAcquisitionRequest(HomeCredentials homeCredentials) {
        ECDSAHelper.enableECDSAProvider();

        try {
            JwtBuilder jwtBuilder = Jwts.builder();
            jwtBuilder.setIssuer(homeCredentials.username);
            jwtBuilder.setSubject(homeCredentials.clientIdentifier);
            jwtBuilder.setIssuedAt(new Date());
            jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + 60000));
            jwtBuilder.signWith(SignatureAlgorithm.ES256, homeCredentials.privateKey);

            return jwtBuilder.compact();
        } catch (Exception e) {
            throw new SecurityException(e.getMessage(), e.getCause());
        }
    }

    public static String convertX509ToPEM(X509Certificate signedCertificate) throws IOException {
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(signedCertificate);
        pemWriter.close();
        return signedCertificatePEMDataStringWriter.toString();
    }

    public static String convertPrivateKeyToPEM(PrivateKey privateKey) throws IOException {
        StringWriter privateKeyPEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(privateKeyPEMDataStringWriter);
        pemWriter.writeObject(privateKey);
        pemWriter.close();
        return privateKeyPEMDataStringWriter.toString();
    }

    public static X509Certificate convertPEMToX509(String pemCertificate) throws IOException, CertificateException {
        StringReader reader = new StringReader(pemCertificate);
        PemReader pr = new PemReader(reader);
        PemObject pemObject = pr.readPemObject();
        X509CertificateHolder certificateHolder = new X509CertificateHolder(pemObject.getContent());
        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateHolder);
    }

    public static PrivateKey convertPEMToPrivateKey(String pemPrivatekey) throws IOException {
        StringReader reader = new StringReader(pemPrivatekey);
        PEMParser pemParser = new PEMParser(reader);
        Object o = pemParser.readObject();
        KeyPair kp = new JcaPEMKeyConverter().setProvider(PROVIDER_NAME).getKeyPair((PEMKeyPair) o);
        return kp.getPrivate();
    }

    public static PublicKey convertPEMToPublicKey(String pemPublickey) throws IOException {
        StringReader reader = new StringReader(pemPublickey);
        PEMParser pemParser = new PEMParser(reader);
        Object o = pemParser.readObject();
        KeyPair kp = new JcaPEMKeyConverter().setProvider(PROVIDER_NAME).getKeyPair((PEMKeyPair) o);
        return kp.getPublic();
    }
}
