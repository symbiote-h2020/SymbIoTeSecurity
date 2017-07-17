package eu.h2020.symbiote.security.commons;

import com.fasterxml.jackson.annotation.JsonIgnore;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import io.jsonwebtoken.Claims;
import org.springframework.data.annotation.Transient;

/**
 * Class that defines the SymbIoTe JWS token
 * <p>
 * TODO R3 unify the duplicated claims handling @{@link Claims} and
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 * @author Elena Garrido (ATOS)
 * @author Nemanja Ignjatov (UNIVIE)
 * @{@link eu.h2020.symbiote.security.commons.jwt.JWTClaims}
 */
public class Token {
    public final static String JWT_CLAIMS_TTYPE = SecurityConstants.CLAIM_NAME_TOKEN_TYPE;

    private String id = "";
    private String token = "";
    // TODO rework it to be the HOME,FOREIGN,GUEST  enum
    private IssuingAuthorityType type = IssuingAuthorityType.NULL;

    @Transient
    private Claims claims;

    public Token() {
        // used by JPA
    }

    /**
     * The token is validated using the issuer public key found in the string.
     *
     * @param token compacted signed token string
     */
    public Token(String token) throws ValidationException {
        this.setToken(token);
    }

    public String getToken() {
        return token;
    }

    /**
     * @param token compacted signed token string
     */
    public void setToken(String token) throws ValidationException {
        ValidationStatus validationStatus = JWTEngine.validateTokenString(token);
        if (validationStatus != ValidationStatus.VALID) {
            throw new ValidationException("Provided token string is not valid: " + validationStatus);
        }
        this.token = token;
        this.setClaims(JWTEngine.getClaims(token));
    }

    @JsonIgnore
    public Claims getClaims() {
        return claims;
    }

    public void setClaims(Claims claims) {
        this.claims = claims;
        this.id = claims.getId();
        this.type = IssuingAuthorityType.valueOf((String) claims.get(SecurityConstants.CLAIM_NAME_TOKEN_TYPE));
    }

    /**
     * stored in JWT_CLAIMS_TTYPE attribute
     *
     * @return the type of this token stating if it was issued by Core or a Platform
     */
    public IssuingAuthorityType getType() {
        return type;
    }

    public String getId() {
        return id;
    }

    @Override
    public String toString() {
        return token;
    }
}
