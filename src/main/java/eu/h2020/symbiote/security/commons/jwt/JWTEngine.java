package eu.h2020.symbiote.security.commons.jwt;

import android.util.Base64;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Set of functions for generating JSON Web Tokens (JWT).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class JWTEngine {

    private JWTEngine() {
    }

    /**
     * Retrieves claims from given jwt String
     *
     * @param jwtString to get claims from
     * @return claims deserialized from the jwt
     * @throws ValidationException on parse exception.
     */
    public static Claims getClaims(String jwtString) throws ValidationException {
        try {
            ECDSAHelper.enableECDSAProvider();
            JWTClaims claims = getClaimsFromToken(jwtString);
            //Convert IPK claim to publicKey for validation
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(claims.getIpk(), Base64.DEFAULT));
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // retrieve the claims
            return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(jwtString).getBody();
            // validate the jwt using the claims parser
        } catch (InvalidKeySpecException | MalformedJWTException | NoSuchAlgorithmException e) {
            throw new ValidationException(ValidationException.JSON_WEB_TOKEN_COULD_NOT_BE_VALIDATED + e.getMessage(), e);
        }
    }

    /**
     * Validates the jwt string using a given public key
     *
     * @param jwtString JSON Web Token to be validated and initialized
     * @param publicKey   issuer's public key
     * @return validation status
     * @throws ValidationException on other errors
     */
    public static ValidationStatus validateTokenString(String jwtString, PublicKey publicKey) throws
            ValidationException {
        try {
            ECDSAHelper.enableECDSAProvider();

            Jwts.parser()
                    .setSigningKey(publicKey)
                    .parseClaimsJws(jwtString);
            return ValidationStatus.VALID;
        } catch (ExpiredJwtException e) {
            return ValidationStatus.EXPIRED_TOKEN;
        } catch (SignatureException e) {
            return ValidationStatus.INVALID_TRUST_CHAIN;
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException e) {
            throw new ValidationException(ValidationException.JSON_WEB_TOKEN_COULD_NOT_BE_VALIDATED + e.getMessage(), e);
        }
    }

    /**
     * Validates the given jwt string
     *
     * @param jwtString JWT to be validated
     * @return validation status
     * @throws ValidationException on validation error
     */
    public static ValidationStatus validateTokenString(String jwtString) throws ValidationException {
        try {
            ECDSAHelper.enableECDSAProvider();
            JWTClaims claims = getClaimsFromToken(jwtString);
            //Convert IPK claim to publicKey for validation
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(claims.getIpk(), Base64.DEFAULT));
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // validate the jwt using the claims parser
            return validateTokenString(jwtString, publicKey);
        } catch (InvalidKeySpecException | MalformedJWTException | NoSuchAlgorithmException e) {
            throw new ValidationException(ValidationException.JSON_WEB_TOKEN_COULD_NOT_BE_VALIDATED + e.getMessage(), e);
        }
    }

    public static JWTClaims getClaimsFromToken(String jwtString) throws MalformedJWTException {
        HashMap<String, Object> retMap = new HashMap<>();
        String[] jwtParts = jwtString.split("\\.");
        if (jwtParts.length < SecurityConstants.JWT_PARTS_COUNT) {
            throw new MalformedJWTException();
        }
        //Get second part of the JWT
        String jwtBody = jwtParts[1];

        String claimsString = new String(Base64.decode(jwtBody, Base64.DEFAULT));

        ObjectMapper mapper = new ObjectMapper();

        Map<String, Object> claimsMap;

        try {
            claimsMap = mapper.readValue(claimsString, new TypeReference<Map<String, String>>() {
            });

            Map<String, String> attributes = new HashMap<>();
            Set<String> jwtKeys = claimsMap.keySet();
            for (String key : jwtKeys) {
                Object value = claimsMap.get(key);
                if (key.startsWith(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX))
                    attributes.put(key.substring(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX.length()), (String)
                            value);
                else
                    retMap.put(key, value);
            }

            //Extracting claims from JWT claims map
            return new JWTClaims(retMap, attributes);
        } catch (IOException | NumberFormatException e) {
            throw new MalformedJWTException(e);
        }
    }

}

