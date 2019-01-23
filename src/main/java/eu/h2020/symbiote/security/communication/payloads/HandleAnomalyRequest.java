package eu.h2020.symbiote.security.communication.payloads;

import eu.h2020.symbiote.security.commons.enums.EventType;

/**
 * Class that defines structure of payload needed to report detected anomaly.
 *
 * @author Piotr Jakubowski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class HandleAnomalyRequest {

    private String anomalyIdentifier = "";
    private EventType eventType;
    private long timestamp = 0;
    private long duration = 0;
    public HandleAnomalyRequest() {
    }
    /**
     * Standard constructor for creating HandleAnomalyRequest.
     *
     * @param anomalyIdentifier anomaly identifier created from EventLogRequest
     * @param eventType         type  of incoming event
     * @param timestamp         time of event in millis
     * @param duration          duration of blockade
     */
    public HandleAnomalyRequest(String anomalyIdentifier, EventType eventType,
                                long timestamp, long duration) {
        this.setAnomalyIdentifier(anomalyIdentifier);
        this.setEventType(eventType);
        this.setTimestamp(timestamp);
        this.setDuration(duration);
    }

    public String getAnomalyIdentifier() {
        return anomalyIdentifier;
    }

    public void setAnomalyIdentifier(String anomalyIdentifier) {
        this.anomalyIdentifier = anomalyIdentifier;
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
