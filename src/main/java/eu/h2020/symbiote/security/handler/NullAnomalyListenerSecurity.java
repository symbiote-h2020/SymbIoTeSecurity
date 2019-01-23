package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.commons.enums.AnomalyDetectionVerbosityLevel;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;

import java.util.Optional;

public class NullAnomalyListenerSecurity implements IAnomalyListenerSecurity {

    @Override
    public boolean insertBlockedActionEntry(HandleAnomalyRequest handleAnomalyRequest) {
        return false;
    }

    @Override
    public boolean isBlocked(Optional<String> username, Optional<String> clientId, Optional<String> jti, Optional<String> componentId, Optional<String> platformId, EventType eventType) {
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

    @Override
    public boolean clearBlockedActions() {
        return false;
    }


}
