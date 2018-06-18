package eu.h2020.symbiote.security.commons;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import io.jsonwebtoken.Claims;
import org.springframework.data.annotation.Transient;

/**
 * Class that defines the SymbIoTe JWS Coupon String
 * <p>
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 * @see eu.h2020.symbiote.security.commons.jwt.JWTClaims
 */
public class Coupon {

    private final String id;
    private final String couponString;
    private final Type type;

    @Transient
    private Claims claims;

    /**
     * The coupon is validated using the issuer public key found in the string.
     *
     * @param couponString compacted signed couponString string
     */

    @JsonCreator
    public Coupon(@JsonProperty("couponString") String couponString) throws ValidationException {
        ValidationStatus validationStatus = JWTEngine.validateJWTString(couponString);
        if (validationStatus != ValidationStatus.VALID) {
            throw new ValidationException("Provided coupon string is not valid: " + validationStatus);
        }
        this.couponString = couponString;
        this.claims = JWTEngine.getClaims(couponString);
        this.id = claims.getId();
        this.type = Type.valueOf((String) claims.get(SecurityConstants.CLAIM_NAME_TOKEN_TYPE));
    }

    public String getCoupon() {
        return couponString;
    }


    @JsonIgnore
    public Claims getClaims() {
        return claims;
    }

    /**
     * stored in JWT_CLAIMS_TTYPE attribute
     *
     * @return the type of this couponString stating if it was issued by Core or a Platform
     */
    public Type getType() {
        return type;
    }

    public String getId() {
        return id;
    }

    @Override
    public String toString() {
        return couponString;
    }

    public enum Type {
        DISCRETE,
        PERIODIC,
        NULL
    }
}
