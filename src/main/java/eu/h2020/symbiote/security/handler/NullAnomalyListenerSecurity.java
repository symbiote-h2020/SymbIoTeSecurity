package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.commons.enums.AnomalyDetectionVerbosityLevel;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;

public class NullAnomalyListenerSecurity implements IAnomalyListenerSecurity {

    @Override
    public Boolean insertBlockedActionEntry(HandleAnomalyRequest handleAnomalyRequest) {
        return false;
    }

    @Override
    public Boolean isBlocked(String username, EventType eventType) {
        return false;
    }
    
    @Override
    public AnomalyDetectionVerbosityLevel getVerbosityLevel() {
        return AnomalyDetectionVerbosityLevel.DISABLED;
    }

    @Override
    public EventLogRequest prepareEventLogRequest(EventLogRequest eventLogRequest) {
        return null;
    }
}
