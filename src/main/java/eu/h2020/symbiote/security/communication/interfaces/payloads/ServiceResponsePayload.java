package eu.h2020.symbiote.security.communication.interfaces.payloads;

import java.security.SignedObject;

/**
 * Utility class for containing the service response payload in the challenge-response procedure.
 *
 * @author Daniele Caldarola (CNIT)
 */
public class ServiceResponsePayload {

    private String hashedTimestamp2;
    private Long timestamp2;

    public ServiceResponsePayload(String hashedTimestamp2, Long timestamp2) {
        this.hashedTimestamp2 = hashedTimestamp2;
        this.timestamp2 = timestamp2;
    }

    public String getHashedTimestamp2() {
        return hashedTimestamp2;
    }

    public void setHashedTimestamp2(String hashedTimestamp2) {
        this.hashedTimestamp2 = hashedTimestamp2;
    }

    public Long getTimestamp2() {
        return timestamp2;
    }

    public void setTimestamp2(Long timestamp2) {
        this.timestamp2 = timestamp2;
    }
}
