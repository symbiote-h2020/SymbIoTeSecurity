package eu.h2020.symbiote.security.utils;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * R3 compliant Authorization token (JWS) builder.
 */
public class DummyTokenIssuer {

    private static SecureRandom random = new SecureRandom();

    public static String buildAuthorizationToken(String userId, Map<String, String> attributes, byte[] userPublicKey,
                                                 Token.Type tokenType, Long tokenValidity, String
                                                         deploymentID, PublicKey aamPublicKey, PrivateKey aamPrivateKey, SignatureType signatureType) {
        ECDSAHelper.enableECDSAProvider();

        String jti = String.valueOf(random.nextInt());
        Map<String, Object> claimsMap = new HashMap<>();

        // Insert AAM Public Key
        claimsMap.put("ipk", Base64.getEncoder().encodeToString(aamPublicKey.getEncoded()));

        //Insert issuee Public Key
        claimsMap.put("spk", Base64.getEncoder().encodeToString(userPublicKey));

        //Add symbIoTe related attributes to token
        if (attributes != null && !attributes.isEmpty()) {
            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                claimsMap.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + entry.getKey(), entry.getValue());
            }
        }

        //Insert token type
        claimsMap.put(SecurityConstants.CLAIM_NAME_TOKEN_TYPE, tokenType);

        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setClaims(claimsMap);
        jwtBuilder.setId(jti);
        jwtBuilder.setIssuer(deploymentID);
        jwtBuilder.setSubject(userId);
        jwtBuilder.setIssuedAt(new Date());
        jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + tokenValidity));
        switch (signatureType) {
            case PROPER:
                jwtBuilder.signWith(SignatureAlgorithm.ES256, aamPrivateKey);
                break;
            case ABUSING:
                jwtBuilder.signWith(SignatureAlgorithm.HS256, aamPublicKey.getEncoded());
                break;
            case NONE:
                // no signature
                break;
        }
        return jwtBuilder.compact();
    }

    public enum SignatureType {
        /**
         * ES256
         */
        PROPER,
        /**
         * using know public key as secret
         */
        ABUSING,
        /**
         * hacking by JWT spec
         */
        NONE
    }
}
