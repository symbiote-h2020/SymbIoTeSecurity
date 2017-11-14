package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/**
 * Utility class containing helper methods for PKI related operation (keys, certificates, conversions)
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class CryptoHelper {
    // Provider is used from the implementation
    public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    public static final String illegalSign = "@";

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

    public static String convertKeyToPEM(Key key) throws IOException {
        StringWriter keyPEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(keyPEMDataStringWriter);
        pemWriter.writeObject(key);
        pemWriter.close();
        return keyPEMDataStringWriter.toString();
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

    /**
     * @param homeAAMCertificate actor's homeAAM certificate
     * @param username           actor's name
     * @param clientId           actor's client id
     * @param clientKey          actor's key pair
     * @return String certificate signing request
     * @throws IOException
     */
    public static String buildCertificateSigningRequestPEM(X509Certificate homeAAMCertificate, String username, String clientId, KeyPair clientKey) throws IOException, InvalidArgumentsException {
        if (username.contains(illegalSign) || clientId.contains(illegalSign))
            throw new InvalidArgumentsException();

        try {
            String cn = "CN=" + username + "@" + clientId + "@" + homeAAMCertificate.getSubjectX500Principal().getName().split("CN=")[1].split(",")[0];
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    new X500Principal(cn), clientKey.getPublic());
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
            ContentSigner signer = csBuilder.build(clientKey.getPrivate());
            PKCS10CertificationRequest csr = p10Builder.build(signer);
            StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
            pemWriter.writeObject(csr);
            pemWriter.close();
            return signedCertificatePEMDataStringWriter.toString();
        } catch (OperatorCreationException e) {
            throw new SecurityException(e.getMessage(), e.getCause());
        }
    }

    /**
     * @param platformId platform's id
     * @param keyPair    actor's key pair
     * @return String platform certificate signing request
     * @throws IOException
     */
    public static String buildPlatformCertificateSigningRequestPEM(String platformId, KeyPair keyPair) throws IOException, InvalidArgumentsException {
        if (platformId.contains(illegalSign))
            throw new InvalidArgumentsException();

        try {
            String cn = "CN=" + platformId;
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    new X500Principal(cn), keyPair.getPublic());
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
            ContentSigner signer = csBuilder.build(keyPair.getPrivate());
            PKCS10CertificationRequest csr = p10Builder.build(signer);
            StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
            pemWriter.writeObject(csr);
            pemWriter.close();
            return signedCertificatePEMDataStringWriter.toString();
        } catch (OperatorCreationException e) {
            throw new SecurityException(e.getMessage(), e.getCause());
        }
    }

    public static String buildComponentCertificateSigningRequestPEM(String componentId, String platformId, KeyPair keyPair) throws
            InvalidArgumentsException,
            IOException {
        if (platformId.contains(illegalSign) || componentId.contains(illegalSign))
            throw new InvalidArgumentsException();

        try {
            String cn = "CN=" + componentId + "@" + platformId;
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    new X500Principal(cn), keyPair.getPublic());
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
            ContentSigner signer = csBuilder.build(keyPair.getPrivate());
            PKCS10CertificationRequest csr = p10Builder.build(signer);
            StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
            pemWriter.writeObject(csr);
            pemWriter.close();
            return signedCertificatePEMDataStringWriter.toString();
        } catch (OperatorCreationException e) {
            throw new SecurityException(e.getMessage(), e.getCause());
        }
    }

    public static PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(String pem) {
        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream;
        try {
            pemStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException ex) {
            throw new SecurityException(ex.getMessage(), ex.getCause());
        }
        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = new PEMParser(pemReader);
        try {
            Object parsedObj = pemParser.readObject();

            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObj;
            }
        } catch (IOException ex) {
            throw new SecurityException(ex.getMessage(), ex.getCause());
        }
        return csr;
    }
}
