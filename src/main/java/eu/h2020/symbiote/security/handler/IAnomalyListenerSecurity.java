package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.commons.enums.AnomalyDetectionVerbosityLevel;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;

import java.util.Optional;

/**
 * Used to manage blocked users due anomalies detection.
 *
 * @author Piotr Jakubowski (PSNC)
 */
public interface IAnomalyListenerSecurity {
    /**
     * Used to insert entry connected with detected anomaly.
     *
     * @param handleAnomalyRequest request with data about detected anomaly
     * @return true if entry successfully inserted
     */
    boolean insertBlockedActionEntry(HandleAnomalyRequest handleAnomalyRequest);

    /**
     * Used to check if specific token/user/client/component is blocked for specified event type
     * @param username username
     * @param clientId clientId
     * @param jti jti of the token
     * @param componentId componentId
     * @param platformId platform in which component is registered
     * @param eventType eventType
     * @return true if anomaly was detected and action should be blocked.
     */
    boolean isBlocked(Optional<String> username, Optional<String> clientId, Optional<String> jti, Optional<String> componentId, Optional<String> platformId, EventType eventType);

    AnomalyDetectionVerbosityLevel getVerbosityLevel();

    EventLogRequest prepareEventLogRequest(EventLogRequest eventLogRequest);

    /**
     * used to clear database from all blocked actions
     *
     * @return
     */
    boolean clearBlockedActions();
}