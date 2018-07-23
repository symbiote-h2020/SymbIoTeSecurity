package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMKeyPair;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.spongycastle.openssl.jcajce.JcaPEMWriter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

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
    public static final String FIELDS_DELIMITER = "@";

    public static KeyPair createKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(SecurityConstants.CURVE_NAME);
        KeyPairGenerator g = KeyPairGenerator.getInstance(SecurityConstants.KEY_PAIR_GEN_ALGORITHM, BouncyCastleProvider
                .PROVIDER_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        return g.generateKeyPair();
    }

    /**
     * @param homeCredentials users/component credentials
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

    /**
     * @param homeCredentials users/component credentials
     * @return String loginRequest
     * @throws SecurityException error during creation of loginRequest
     */
    public static String buildCouponAcquisitionRequest(HomeCredentials homeCredentials, String platformId) {
        ECDSAHelper.enableECDSAProvider();

        try {
            JwtBuilder jwtBuilder = Jwts.builder();
            jwtBuilder.setIssuer(homeCredentials.username + CryptoHelper.FIELDS_DELIMITER + homeCredentials.clientIdentifier);
            jwtBuilder.setSubject(platformId);
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
        return signedCertificatePEMDataStringWriter.toString().replace("\r", "");
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
    public static String buildCertificateSigningRequestPEM(X509Certificate homeAAMCertificate, String username, String clientId, KeyPair clientKey) throws
            IOException,
            InvalidArgumentsException {
        if (username.contains(FIELDS_DELIMITER) || clientId.contains(FIELDS_DELIMITER))
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
     * @param serviceId platform's or smart space's id
     * @param keyPair   actor's key pair
     * @return String service certificate signing request
     * @throws IOException
     */
    public static String buildServiceCertificateSigningRequestPEM(String serviceId, KeyPair keyPair) throws
            IOException,
            InvalidArgumentsException {
        if (serviceId.contains(FIELDS_DELIMITER))
            throw new InvalidArgumentsException();

        try {
            String cn = "CN=" + serviceId;
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
        if (platformId.contains(FIELDS_DELIMITER) || componentId.contains(FIELDS_DELIMITER))
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

    public static boolean isClientCertificateChainTrusted(String coreAAMCertificateString,
                                                          String signingAAMCertificateString,
                                                          String clientCertificateString) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            IOException {

        // convert certificates to X509
        X509Certificate coreAAMCertificate = CryptoHelper.convertPEMToX509(coreAAMCertificateString);
        X509Certificate clientCertificate = CryptoHelper.convertPEMToX509(clientCertificateString);
        X509Certificate signingAAMCertificate = CryptoHelper.convertPEMToX509(signingAAMCertificateString);

        // Create the selector that specifies the starting certificate
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(clientCertificate);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        TrustAnchor trustAnchor = new TrustAnchor(coreAAMCertificate, null);
        trustAnchors.add(trustAnchor);

        // List of certificates to build the path from
        List<X509Certificate> certsOnPath = new ArrayList<>();
        certsOnPath.add(signingAAMCertificate);
        certsOnPath.add(clientCertificate);

        /*
         * If build() returns successfully, the certificate is valid. More details
         * about the valid path can be obtained through the PKIXCertPathBuilderResult.
         * If no valid path can be found, a CertPathBuilderException is thrown.
         */
        try {
            // Create the selector that specifies the starting certificate
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, target);
            // Disable CRL checks (this is done manually as additional step)
            params.setRevocationEnabled(false);

            // Specify a list of certificates on path
            CertStore validatedPathCertsStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(certsOnPath), "BC");
            params.addCertStore(validatedPathCertsStore);

            // Build and verify the certification chain
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(params);
            // path should have 1 cert in symbIoTe architecture (if client is Core component - used in componentSecurityHandler)
            if (coreAAMCertificateString.equals(signingAAMCertificateString)) {
                return result.getCertPath().getCertificates().size() == 1;
            }
            // path should have 2 certs in symbIoTe architecture
            return result.getCertPath().getCertificates().size() == 2;
        } catch (CertPathBuilderException | InvalidAlgorithmParameterException e) {
            return false;
        }
    }
}
