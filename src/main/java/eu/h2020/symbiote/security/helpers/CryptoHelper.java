package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

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

    public static SignedObject objectToSignedObject(Serializable toSign, PrivateKey key) throws IOException {
        try {
            Signature signature = Signature.getInstance(SecurityConstants.SIGNATURE_ALGORITHM);
            return new SignedObject(toSign, key, signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new SecurityException(e.getMessage(), e.getCause());
        }
    }

    public static boolean verifySignedObject(SignedObject signedObject, PublicKey key) {
        try {
            Signature signature = Signature.getInstance(SecurityConstants.SIGNATURE_ALGORITHM);
            return signedObject.verify(key, signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new SecurityException(e.getMessage(), e.getCause());
        }
    }

    public static String signedObjectToString(SignedObject signedObject) throws IOException {
        return CryptoHelper.objectToString(signedObject);
    }

    public static SignedObject stringToSignedObject(String stringObject) throws IOException {
        return stringToObject(stringObject, SignedObject.class);
    }

    private static String objectToString(Serializable object) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(object);
        objectOutputStream.close();
        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
    }

    private static <T extends Serializable> T stringToObject(String string, Class<T> clazz) throws IOException {
        byte[] bytes = Base64.getDecoder().decode(string.getBytes());
        T object = null;
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(bytes));
            object = (T) objectInputStream.readObject();
        } catch (ClassNotFoundException | ClassCastException e) {
            throw new SecurityException(e.getMessage(), e.getCause());
        }
        return object;
    }

    public static KeyPair createKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(SecurityConstants.CURVE_NAME);
        KeyPairGenerator g = KeyPairGenerator.getInstance(SecurityConstants.KEY_PAIR_GEN_ALGORITHM, BouncyCastleProvider
                .PROVIDER_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        return g.generateKeyPair();
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

    public static PrivateKey convertPEMToPrivateKey(String pemPrivatekey) throws IOException, CertificateException {
        StringReader reader = new StringReader(pemPrivatekey);
        PEMParser pemParser = new PEMParser(reader);
        Object o = pemParser.readObject();
        KeyPair kp = new JcaPEMKeyConverter().setProvider(PROVIDER_NAME).getKeyPair((PEMKeyPair) o);
        return kp.getPrivate();
    }
}
