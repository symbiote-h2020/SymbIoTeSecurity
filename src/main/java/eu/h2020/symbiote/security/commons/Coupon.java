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

    private String id = "";
    private String couponString = "";
    private Type type = Type.NULL;

    @Transient
    private Claims claims;

    public Coupon() {
        // used by JPA
    }

    /**
     * The coupon is validated using the issuer public key found in the string.
     *
     * @param couponString compacted signed couponString string
     */

    @JsonCreator
    public Coupon(@JsonProperty("couponString") String couponString) throws ValidationException {
        this.setCoupon(couponString);
    }

    public String getCoupon() {
        return couponString;
    }

    /**
     * @param coupon compacted signed couponString string
     */
    private void setCoupon(String coupon) throws ValidationException {
        ValidationStatus validationStatus = JWTEngine.validateJWTString(coupon);
        if (validationStatus != ValidationStatus.VALID) {
            throw new ValidationException("Provided coupon string is not valid: " + validationStatus);
        }
        this.couponString = coupon;
        this.setClaims(JWTEngine.getClaims(coupon));
    }

    @JsonIgnore
    public Claims getClaims() {
        return claims;
    }

    public void setClaims(Claims claims) {
        this.claims = claims;
        this.id = claims.getId();
        this.type = Type.valueOf((String) claims.get(SecurityConstants.CLAIM_NAME_TOKEN_TYPE));
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
