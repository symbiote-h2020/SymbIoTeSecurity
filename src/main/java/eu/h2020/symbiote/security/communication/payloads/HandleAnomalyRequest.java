package eu.h2020.symbiote.security.communication.payloads;

import eu.h2020.symbiote.security.commons.enums.EventType;

/**
 * Class that defines structure of payload needed to report detected anomaly.
 *
 * @author Piotr Jakubowski (PSNC)
 */
public class HandleAnomalyRequest {

    private String username = "";
    private String clientIdentifier = "";
    private String jti = "";
    private EventType eventType;
    private long timestamp = 0;
    private long duration = 0;

    public HandleAnomalyRequest() {
    }

    /**
     * Standard constructor for creating HandleAnomalyRequest.
     * @param username             user's name
     * @param clientIdentifier     identifier of client
     * @param jti                  jti
     * @param eventType            type  of incoming event
     * @param timestamp            time of event in millis
     */
    public HandleAnomalyRequest(String username, String clientIdentifier, String jti, EventType eventType,
                                long timestamp, long duration) {
        this.setUsername(username);
        this.setClientIdentifier(clientIdentifier);
        this.setJti(jti);
        this.setEventType(eventType);
        this.setTimestamp(timestamp);
        this.setDuration(duration);
    }


    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getClientIdentifier() {
        return clientIdentifier;
    }

    public void setClientIdentifier(String clientIdentifier) {
        this.clientIdentifier = clientIdentifier;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public EventType getEventType() {
        return eventType;
    }

    public void setEventType(EventType eventType) {
        this.eventType = eventType;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public long getDuration() {
        return duration;
    }

    public void setDuration(long duration) {
        this.duration = duration;
    }
}
