package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.SecurityCredentials;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.ZonedDateTime;
import java.util.*;


/**
 * Provides helper methods to handle client-service authentication procedure.
 * <p>
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 */
public class MutualAuthenticationHelper {

    private static final Long THRESHOLD = new Long(3600000); // XXX: has to be reduced and put on a proper container or in the boostrap

    /**
     * Utility class to hash a string with SHA-256
     *
     * @param stringToHash certificate of the service host used to encrypt the challenge
     * @return the hexadecimal hashed string
     */
    public static String hashSHA256(String stringToHash) throws
            NoSuchAlgorithmException {

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] byteHash = messageDigest.digest(stringToHash.getBytes(StandardCharsets.UTF_8));
        String hexHash = new String(Hex.encode(byteHash)); // byte to hex converter to get the hashed value in hexadecimal
        messageDigest.reset();

        return hexHash;
    }

    /**
     * Used by the application to generate the challenge to be attached to the business query
     * so that the service can confirm that the client should posses provided tokens
     *
     * @param authorizationCredentials matching the set of tokens used in the business query
     * @param attachCertificates       true if application and signing platform certificates must be sent along with the
     *                                 security credentials
     * @return the required payload (the "challenge" in the challenge-response procedure)
     */
    public static SecurityRequest getSecurityRequest(Set<AuthorizationCredentials> authorizationCredentials,
                                                     boolean attachCertificates) throws
            NoSuchAlgorithmException {

        Long timestamp1 = ZonedDateTime.now().toInstant().toEpochMilli();
        Iterator<AuthorizationCredentials> iteratorAC = authorizationCredentials.iterator();
        Set<SecurityCredentials> securityCredentialsSet = new LinkedHashSet<SecurityCredentials>();

        while (iteratorAC.hasNext()) {
            AuthorizationCredentials authorizationCredentialsSetElement = iteratorAC.next();

            String token = authorizationCredentialsSetElement.authorizationToken.toString();
            String hexHash = hashSHA256(authorizationCredentialsSetElement.authorizationToken.toString() + timestamp1.toString());

            JwtBuilder jwtBuilder = Jwts.builder();
            jwtBuilder.setId(authorizationCredentialsSetElement.authorizationToken.getClaims().getId()); // jti
            jwtBuilder.setIssuer(authorizationCredentialsSetElement.authorizationToken.getClaims().getIssuer()); // iss
            jwtBuilder.claim("ipk", authorizationCredentialsSetElement.authorizationToken.getClaims().get("spk"));
            jwtBuilder.claim("hash", hexHash);
            jwtBuilder.signWith(SignatureAlgorithm.ES256, authorizationCredentialsSetElement.homeCredentials.privateKey);
            String authenticationChallenge = jwtBuilder.compact();

            if (attachCertificates) {
                String clientCertificate = authorizationCredentialsSetElement.homeCredentials.certificate.getCertificateString();
                String signingAAMCertificate = authorizationCredentialsSetElement.homeCredentials.homeAAM.getCertificate().getCertificateString();
                securityCredentialsSet.add(new SecurityCredentials(token, authenticationChallenge, clientCertificate, signingAAMCertificate));
            } else {
                securityCredentialsSet.add(new SecurityCredentials(token, authenticationChallenge));
            }
        }

        return new SecurityRequest(securityCredentialsSet, timestamp1);
    }

    // TODO @Mikolaj: How to handle the related isSecurityRequestVerified() foro guest tokens?
    public static SecurityRequest getSecurityRequest(Token guestToken) throws
            NoSuchAlgorithmException {

        Long timestamp1 = ZonedDateTime.now().toInstant().toEpochMilli();
        Set<SecurityCredentials> securityCredentialsSet = new LinkedHashSet<SecurityCredentials>();
        securityCredentialsSet.add(new SecurityCredentials(guestToken.toString()));

        return new SecurityRequest(securityCredentialsSet, timestamp1);
    }

    /**
     * Used by the service to handle the challenge verification
     *
     * @param securityRequest contains client tokens and "challenge" for client authentication
     * @return true if the client should be in possession of the given tokens
     */
    public static boolean isSecurityRequestVerified(SecurityRequest securityRequest) throws
            NoSuchAlgorithmException,
            MalformedJWTException,
            IOException,
            ValidationException {

        Long timestamp2 = ZonedDateTime.now().toInstant().toEpochMilli();

        Set<SecurityCredentials> securityCredentialsSet = securityRequest.getSecurityCredentials();
        Long timestamp1 = securityRequest.getTimestamp();

        Iterator<SecurityCredentials> iteratorSCS = securityCredentialsSet.iterator();

        while (iteratorSCS.hasNext()) {
            SecurityCredentials securityCredentialsSetElement = iteratorSCS.next();

            String applicationToken = securityCredentialsSetElement.getToken();
            String applicationPublicKeyPEM = JWTEngine.getClaimsFromToken(applicationToken).getSpk();
            PublicKey applicationPublicKey = CryptoHelper.convertPEMToPublicKey(applicationPublicKeyPEM);

            String challengeJWS = securityCredentialsSetElement.getAuthenticationChallenge();
            String challengeHash = Jwts.parser().setSigningKey(applicationPublicKey).parseClaimsJws(challengeJWS).getBody().get("hash").toString();
            String calculatedHash = hashSHA256(securityCredentialsSetElement.getToken() + timestamp1.toString());
            Long deltaT = timestamp2 - timestamp1;

            // check challenge is ok
            if (!Objects.equals(calculatedHash, challengeHash) || (deltaT >= THRESHOLD)) {
                return false;
            }

            // check token is ok
            if (JWTEngine.validateTokenString(applicationToken, applicationPublicKey) != ValidationStatus.VALID) {
                return false;
            }
        }

        return true;
    }

    /**
     * Used by the service to generate the response payload to be encapsulated in a JWS required by
     * the application to confirm the service authenticity.
     *
     * @param servicePrivateKey used the sign the JWS response
     * @param timestamp2        used in the response payload
     * @return the required payload
     */
    public static String getServiceResponse(PrivateKey servicePrivateKey,
                                            Long timestamp2) throws
            NoSuchAlgorithmException {

        String hashedTimestamp2 = hashSHA256(timestamp2.toString());

        JwtBuilder jwtBuilder = Jwts.builder(); // TODO @Mikolay: some other fields here?
        jwtBuilder.claim("hash", hashedTimestamp2);
        jwtBuilder.claim("timestamp", timestamp2.toString());
        jwtBuilder.signWith(SignatureAlgorithm.ES256, servicePrivateKey);

        return jwtBuilder.compact();
    }

    /**
     * Used by the client to handle the service response encapsulated in a JWS.
     *
     * @param serviceResponse       that should prove the service's authenticity
     * @param serviceCertificate    used verify the payload signature
     * @return true if the service is genuine
     */
    public static boolean isServiceResponseVerified(String serviceResponse,
                                                    Certificate serviceCertificate) throws
            NoSuchAlgorithmException,
            CertificateException {

        Long timestamp3 = ZonedDateTime.now().toInstant().toEpochMilli();
        PublicKey servicePublicKey = serviceCertificate.getX509().getPublicKey();

        Long timestamp2 = Long.valueOf(Jwts.parser().setSigningKey(servicePublicKey).parseClaimsJws(serviceResponse).getBody().get("hash").toString());
        String hashedTimestamp2 = Jwts.parser().setSigningKey(servicePublicKey).parseClaimsJws(serviceResponse).getBody().get("timestamp").toString();

        String calculatedHash = hashSHA256(timestamp2.toString());
        Long deltaT = timestamp3 - timestamp2;

        return Objects.equals(calculatedHash, hashedTimestamp2) && deltaT < THRESHOLD;
    }

}
