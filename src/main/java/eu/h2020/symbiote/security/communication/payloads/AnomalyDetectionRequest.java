package eu.h2020.symbiote.security.communication.payloads;

import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;

import java.sql.Timestamp;

public class AnomalyDetectionRequest {

    public String username;
    public String clientIdentifier;
    public String jti;
    public String eventType;
    public Timestamp timestamp;

    public AnomalyDetectionRequest(String username, String clientIdentifier, String jti, String eventType, Timestamp timestamp) {
        this.username = username;
        this.clientIdentifier = clientIdentifier;
        this.jti = jti;
        this.eventType = eventType;
        this.timestamp = timestamp;
    }

    public AnomalyDetectionRequest(String tokenString, String eventType, Timestamp timestamp) throws WrongCredentialsException {
        JWTClaims claims = null;
        try {
            claims = JWTEngine.getClaimsFromToken(tokenString);
        } catch (MalformedJWTException e) {
            throw new WrongCredentialsException(e.getErrorMessage());
        }
        String[] subjectParts = claims.getSub().split("@");
        System.out.println(claims.getSub());
        this.username = subjectParts[0];

        if (subjectParts.length > 1)
            this.clientIdentifier = subjectParts[1];
        if (subjectParts.length >2)
            this.jti = subjectParts[2];

        this.eventType = eventType;
        this.timestamp = timestamp;
    }

    public AnomalyDetectionRequest() {

    }

}
