package eu.h2020.symbiote.security.dummies;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Mikołaj on 17.07.2017.
 */
public class DummyTokenIssuer {

    private static Log log = LogFactory.getLog(DummyTokenIssuer.class);
    private static SecureRandom random = new SecureRandom();

    public static String generateJWTToken(String userId, Map<String, String> attributes, byte[] userPublicKey,
                                          IssuingAuthorityType deploymentType, Long tokenValidity, String
                                                  deploymentID, PublicKey aamPublicKey, PrivateKey aamPrivateKey)
            throws JWTCreationException {
        ECDSAHelper.enableECDSAProvider();

        String jti = String.valueOf(random.nextInt());
        Map<String, Object> claimsMap = new HashMap<>();

        try {
            // Insert AAM Public Key
            claimsMap.put("ipk", org.apache.commons.codec.binary.Base64.encodeBase64String(aamPublicKey.getEncoded()));

            //Insert issuee Public Key
            claimsMap.put("spk", org.apache.commons.codec.binary.Base64.encodeBase64String(userPublicKey));

            //Add symbIoTe related attributes to token
            if (attributes != null && !attributes.isEmpty()) {
                for (Map.Entry<String, String> entry : attributes.entrySet()) {
                    claimsMap.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + entry.getKey(), entry.getValue());
                }
            }

            //Insert token type based on AAM deployment type (Core or Platform)
            switch (deploymentType) {
                case CORE:
                    claimsMap.put(SecurityConstants.CLAIM_NAME_TOKEN_TYPE, IssuingAuthorityType.CORE);
                    break;
                case PLATFORM:
                    claimsMap.put(SecurityConstants.CLAIM_NAME_TOKEN_TYPE, IssuingAuthorityType.PLATFORM);
                    break;
                case NULL:
                    throw new JWTCreationException("uninitialized deployment type, must be CORE or PLATFORM");
            }

            JwtBuilder jwtBuilder = Jwts.builder();
            jwtBuilder.setClaims(claimsMap);
            jwtBuilder.setId(jti);
            jwtBuilder.setIssuer(deploymentID);
            jwtBuilder.setSubject(userId);
            jwtBuilder.setIssuedAt(new Date());
            jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + tokenValidity));
            jwtBuilder.signWith(SignatureAlgorithm.ES256, aamPrivateKey);

            return jwtBuilder.compact();
        } catch (Exception e) {
            String message = "JWT creation error";
            log.error(message, e);
            throw new JWTCreationException(message, e);
        }
    }
}
