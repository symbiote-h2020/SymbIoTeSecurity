package eu.h2020.symbiote.security.helpers;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token.Type;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.SecurityCredentials;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


/**
 * Provides helper methods to handle client-service authentication procedure.
 * <p>
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 */
public class MutualAuthenticationHelper {

    /**
     * Defines for how long a security response from a remote service should be deemed as valid.
     * MUST not be enlarged without serious consideration.
     * Default value of 60 seconds is reasonable to count for Internet delays.
     */
    public static long SERVICE_RESPONSE_EXPIRATION_TIME = 60;
    private static SecureRandom random = new SecureRandom();
    private static Log log = LogFactory.getLog(MutualAuthenticationHelper.class);

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
     * Used by the application to generate the security request to be attached to the business query
     * so that the service can confirm that the client should posses provided tokens
     *
     * @param authorizationCredentials matching the set of tokens used in the business query
     * @param attachCertificates       true if application and signing platform certificates must be sent along with the
     *                                 security credentials
     * @return the required payload for client's authentication and authorization
     */
    public static SecurityRequest getSecurityRequest(Set<AuthorizationCredentials> authorizationCredentials,
                                                     boolean attachCertificates) throws
            NoSuchAlgorithmException {

        Date timestampDate = new Date();
        // JWT rounds to seconds
        long timestampMilliseconds = timestampDate.getTime() - timestampDate.getTime() % 1000;
        Date expiryDate = new Date(timestampMilliseconds + SERVICE_RESPONSE_EXPIRATION_TIME * 1000);

        Iterator<AuthorizationCredentials> iteratorAC = authorizationCredentials.iterator();
        Set<SecurityCredentials> securityCredentialsSet = new HashSet<>();

        while (iteratorAC.hasNext()) {
            AuthorizationCredentials credentials = iteratorAC.next();

            String token = credentials.authorizationToken.toString();
            String hexHash = hashSHA256(credentials.authorizationToken.toString() + timestampMilliseconds);

            JwtBuilder jwtBuilder = Jwts.builder();
            jwtBuilder.setId(String.valueOf(random.nextInt())); // random -> jti
            jwtBuilder.setSubject(credentials.authorizationToken.getClaims().getId()); // token jti -> sub
            jwtBuilder.setIssuer(credentials.authorizationToken.getClaims().getSubject()); // token sub -> iss
            jwtBuilder.claim("ipk", credentials.authorizationToken.getClaims().get("spk")); // token spk -> ipk
            jwtBuilder.claim("hash", hexHash); // SHA256(token+timestamp)
            jwtBuilder.setIssuedAt(timestampDate); // iat
            jwtBuilder.setExpiration(expiryDate);  // exp
            jwtBuilder.signWith(SignatureAlgorithm.ES256, credentials.homeCredentials.privateKey);
            String authenticationChallenge = jwtBuilder.compact();

            if (attachCertificates) {
                String clientCertificate = credentials.homeCredentials.certificate.getCertificateString();
                String signingAAMCertificate = credentials.homeCredentials.homeAAM.getAamCACertificate().getCertificateString();
                String foreignTokenIssuingAAMCertificate = "";
                // FOREIGN tokens needs extra information
                if (credentials.authorizationToken.getType().equals(Type.FOREIGN))
                    foreignTokenIssuingAAMCertificate = credentials.tokenIssuingAAM.getAamCACertificate().getCertificateString();

                securityCredentialsSet.add(new SecurityCredentials(
                        token,
                        Optional.of(authenticationChallenge),
                        Optional.of(clientCertificate),
                        Optional.of(signingAAMCertificate),
                        Optional.of(foreignTokenIssuingAAMCertificate)));
            } else {
                securityCredentialsSet.add(new SecurityCredentials(
                        token,
                        Optional.of(authenticationChallenge),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty()));
            }
        }

        return new SecurityRequest(securityCredentialsSet, timestampMilliseconds);
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
            ValidationException,
            InvalidKeySpecException {

        Long timestamp2 = new Date().getTime();
        // JWT rounds to seconds
        timestamp2 = timestamp2 - timestamp2 % 1000;
        Long timestamp1 = securityRequest.getTimestamp();

        Set<SecurityCredentials> securityCredentialsSet = securityRequest.getSecurityCredentials();
        Iterator<SecurityCredentials> iteratorSCS = securityCredentialsSet.iterator();

        // guest token scenario
        if (securityCredentialsSet.size() == 1) {
            Type tokenType = Type.valueOf(JWTEngine.getClaimsFromToken(securityCredentialsSet.iterator().next().getToken()).getTtyp());
            if (tokenType.equals(Type.GUEST))
                return true;
        }

        // proper tokens scenario
        while (iteratorSCS.hasNext()) {

            SecurityCredentials securityCredentialsSetElement = iteratorSCS.next();
            KeyFactory keyFactory = KeyFactory.getInstance("EC");

            // tokens' sanity check
            ValidationStatus authorizationTokenValidationStatus = JWTEngine.validateTokenString(securityCredentialsSetElement.getToken());
            ValidationStatus challengeValidationStatus = JWTEngine.validateTokenString(securityCredentialsSetElement.getAuthenticationChallenge());
            if (authorizationTokenValidationStatus != ValidationStatus.VALID || challengeValidationStatus != ValidationStatus.VALID)
                return false;

            // claims extraction
            JWTClaims claimsFromAuthorizationToken = JWTEngine.getClaimsFromToken(securityCredentialsSetElement.getToken());
            JWTClaims claimsFromChallengeToken = JWTEngine.getClaimsFromToken(securityCredentialsSetElement.getAuthenticationChallenge());

            X509EncodedKeySpec keySpecSpk = new X509EncodedKeySpec(Base64.getDecoder().decode(claimsFromAuthorizationToken.getSpk()));
            PublicKey applicationPublicKey = keyFactory.generatePublic(keySpecSpk);

            String challengeJWS = securityCredentialsSetElement.getAuthenticationChallenge();
            String challengeHash = Jwts.parser().setSigningKey(applicationPublicKey).parseClaimsJws(challengeJWS).getBody().get("hash").toString();
            String calculatedHash = hashSHA256(securityCredentialsSetElement.getToken() + timestamp1.toString());
            Long deltaT = timestamp2 - timestamp1;
            Long thresholdMilis = SERVICE_RESPONSE_EXPIRATION_TIME * 1000;

            // check that challengeJWS matches the authorization token

            // token jti -> sub
            if (!claimsFromAuthorizationToken.getJti().equals(claimsFromChallengeToken.getSub()))
                return false;
            // token sub -> iss
            if (!claimsFromAuthorizationToken.getSub().equals(claimsFromChallengeToken.getIss()))
                return false;
            // timestamp1 in iat
            if (!claimsFromChallengeToken.getIat().equals(timestamp1))
                return false;
            // threshold included in exp
            if (!claimsFromChallengeToken.getExp().equals(timestamp1 + thresholdMilis))
                return false;
            // token spk -> ipk
            if (!claimsFromAuthorizationToken.getSpk().equals(claimsFromChallengeToken.getIpk()))
                return false;

            // check challenge is ok SHA256(token+timestamp)
            if (!Objects.equals(calculatedHash, challengeHash) || (deltaT >= thresholdMilis)) {
                return false;
            }

            // signature match - token SPK -> challenge IPK & sign
            X509EncodedKeySpec keySpecIpk = new X509EncodedKeySpec(Base64.getDecoder().decode(claimsFromAuthorizationToken.getSpk()));
            PublicKey challengeIssuerPublicKey = keyFactory.generatePublic(keySpecIpk);
            if (JWTEngine.validateTokenString(challengeJWS, challengeIssuerPublicKey) != ValidationStatus.VALID) {
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
                                            long timestamp2) throws
            NoSuchAlgorithmException {

        String hashedTimestamp2 = hashSHA256(Long.toString(timestamp2));

        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.claim("hash", hashedTimestamp2);
        jwtBuilder.claim("timestamp", Long.toString(timestamp2));
        jwtBuilder.signWith(SignatureAlgorithm.ES256, servicePrivateKey);

        return jwtBuilder.compact();
    }

    /**
     * Used by the client to handle the service response encapsulated in a JWS.
     *
     * @param serviceResponse    that should prove the service's authenticity
     * @param serviceCertificate used verify the payload signature
     * @return true if the service is genuine
     */
    public static boolean isServiceResponseVerified(String serviceResponse,
                                                    Certificate serviceCertificate) throws
            NoSuchAlgorithmException,
            CertificateException {

        Long currentLocalTimestamp = new Date().getTime();
        // JWT rounds to seconds
        currentLocalTimestamp = currentLocalTimestamp - currentLocalTimestamp % 1000;
        PublicKey servicePublicKey = serviceCertificate.getX509().getPublicKey();

        Long remoteServiceTimestamp;
        String remoteServiceTimestampHash;
        try {
            remoteServiceTimestamp = Long.valueOf(Jwts.parser().setSigningKey(servicePublicKey).parseClaimsJws(serviceResponse).getBody().get("timestamp").toString());
            remoteServiceTimestampHash = Jwts.parser().setSigningKey(servicePublicKey).parseClaimsJws(serviceResponse).getBody().get("hash").toString();
        } catch (io.jsonwebtoken.SignatureException e) {
            log.error("The signature of the service response doesn't match the provided component certificate.");
            throw new CertificateException(e.getMessage());
        }

        String calculatedHash = hashSHA256(remoteServiceTimestamp.toString());
        Long deltaT = Math.abs(currentLocalTimestamp - remoteServiceTimestamp);

        if (!calculatedHash.equals(remoteServiceTimestampHash)) {
            log.error("Service response JWS hash claim doesn't match symbIoTe mutual authentication algorithm");
            return false;
        }

        if (deltaT > SERVICE_RESPONSE_EXPIRATION_TIME * 1000) {
            log.error("Disparity between received timestamp: " + new Date(remoteServiceTimestamp)
                    + " and our local timestamp: " + new Date(currentLocalTimestamp)
                    + " is " + deltaT / 1000 + "seconds, which is over the " + SERVICE_RESPONSE_EXPIRATION_TIME + " seconds allowed validity threshold.");
            return false;
        }
        return true;
    }

}
