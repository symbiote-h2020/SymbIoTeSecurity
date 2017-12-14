package eu.h2020.symbiote.security.communication.payloads;


public class AnomalyDetectionVerbosityLevel {

    private Boolean username = Boolean.FALSE;
    private Boolean clientIdentifier = Boolean.FALSE;
    private Boolean jti = Boolean.FALSE;
    private Boolean platformId = Boolean.FALSE;
    private Boolean eventType = Boolean.FALSE;
    private Boolean timestamp = Boolean.FALSE;
    private Boolean tokenString = Boolean.FALSE;
    private Boolean reason = Boolean.FALSE;


    public AnomalyDetectionVerbosityLevel() {
    }

    public AnomalyDetectionVerbosityLevel(Boolean username, Boolean clientIdentifier, Boolean jti, Boolean platformId,
                                          Boolean eventType, Boolean timestamp, Boolean tokenString, Boolean reason) {
        this.username = username;
        this.clientIdentifier = clientIdentifier;
        this.jti = jti;
        this.platformId = platformId;
        this.eventType = eventType;
        this.timestamp = timestamp;
        this.tokenString = tokenString;
        this.reason = reason;
    }

    public Boolean getUsername() {
        return username;
    }

    public void setUsername() {
        this.username = Boolean.TRUE;
    }

    public Boolean getClientIdentifier() {
        return clientIdentifier;
    }

    public void setClientIdentifier() {
        this.clientIdentifier = Boolean.TRUE;
    }

    public Boolean getJti() {
        return jti;
    }

    public void setJti() {
        this.jti = Boolean.TRUE;
    }

    public Boolean getPlatformId() {
        return platformId;
    }

    public void setPlatformId() {
        this.platformId = Boolean.TRUE;
    }

    public Boolean getEventType() {
        return eventType;
    }

    public void setEventType() {
        this.eventType = Boolean.TRUE;
    }

    public Boolean getTimestamp() {
        return timestamp;
    }

    public void setTimestamp() {
        this.timestamp = Boolean.TRUE;
    }

    public Boolean getTokenString() {
        return tokenString;
    }

    public void setTokenString() {
        this.tokenString = Boolean.TRUE;
    }

    public Boolean getReason() {
        return reason;
    }

    public void setReason() {
        this.reason = Boolean.TRUE;
    }
}
