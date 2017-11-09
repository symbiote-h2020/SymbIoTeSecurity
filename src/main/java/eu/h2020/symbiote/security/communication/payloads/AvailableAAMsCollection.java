package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Available AAMs map wrapper for JAX-RS & Jackson compatibility
 */
public class AvailableAAMsCollection {
    private final Map<String, AAM> availableAAMs;


    @JsonCreator
    public AvailableAAMsCollection(@JsonProperty("availableAAMs") Map<String, AAM> availableAAMs) {
        this.availableAAMs = availableAAMs;
    }

    public Map<String, AAM> getAvailableAAMs() {
        return availableAAMs;
    }
}
