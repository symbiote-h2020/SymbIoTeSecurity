package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;


public class EventLogRequest {

    private String username;
    private String clientIdentifier;
    private String jti;
    private EventType eventType;
    private long timestamp;

    public EventLogRequest(String username,
                           String clientIdentifier,
                           String jti,
                           EventType eventType,
                           long timestamp) {
        this.username = username;
        this.clientIdentifier = clientIdentifier;
        this.jti = jti;
        this.eventType = eventType;
        this.timestamp = timestamp;
    }

    public EventLogRequest(String tokenString,
                           EventType eventType,
                           long timestamp) throws WrongCredentialsException {
        JWTClaims claims;
        try {
            claims = JWTEngine.getClaimsFromToken(tokenString);
        } catch (MalformedJWTException e) {
            throw new WrongCredentialsException(e.getErrorMessage());
        }
        String[] subjectParts = claims.getSub().split("@");
        this.username = subjectParts[0];

        if (subjectParts.length > 1)
            this.clientIdentifier = subjectParts[1];
        if (subjectParts.length > 2)
            this.jti = subjectParts[2];

        this.eventType = eventType;
        this.timestamp = timestamp;
    }

    public EventLogRequest() {
    }

    public String getUsername() {
        return username;
    }

    public String getClientIdentifier() {
        return clientIdentifier;
    }

    public String getJti() {
        return jti;
    }

    public EventType getEventType() {
        return eventType;
    }

    public long getTimestamp() {
        return timestamp;
    }
}
