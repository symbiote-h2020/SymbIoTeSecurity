package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;

/**
 * Class that defines structure of payload needed to log event
 *
 * @author Piotr Jakubowski (PSNC)
 */
public class EventLogRequest {

    private String username = "";
    private String clientIdentifier = "";
    private String jti = "";
    private EventType eventType;
    private long timestamp = 0;

    /**
     * Standard constructor for creating EventLogRequest object prepared for serializing and deserializing.
     * @param username             user's name
     * @param clientIdentifier     identifier of client
     * @param jti                  jti
     * @param eventType            type  of incoming event
     * @param timestamp            time of event in millis
     */
    @JsonCreator
    public EventLogRequest(@JsonProperty("username") String username,
                           @JsonProperty("clientIdentifier") String clientIdentifier,
                           @JsonProperty("jti") String jti,
                           @JsonProperty("eventType") EventType eventType,
                           @JsonProperty("timestamp") long timestamp) {
        this.username = username;
        this.clientIdentifier = clientIdentifier;
        this.jti = jti;
        this.eventType = eventType;
        this.timestamp = timestamp;
    }

    /**
     * Alternative constructor for creating EventLogRequest object. It tries to extract username, clientIdentifier and jti from token.
     * @param tokenString          token from which you can extract username, clientIdentified and jti
     * @param eventType            type of incoming event
     * @param timestamp            time of event in millis
     */
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

        this.jti = claims.getJti();
        this.eventType = eventType;
        this.timestamp = timestamp;
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
