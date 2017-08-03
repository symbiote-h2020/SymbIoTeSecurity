package eu.h2020.symbiote.security.communication.payloads;

import java.util.Map;
import java.util.TreeMap;

/**
 * Available AAMs map wrapper for JAX-RS & Jackson compatibility
 */
public class AvailableAAMsCollection {
    private Map<String, AAM> availableAAMs = new TreeMap<>();

    public AvailableAAMsCollection() {
        // json required
    }

    public AvailableAAMsCollection(Map<String, AAM> availableAAMs) {
        this.availableAAMs = availableAAMs;
    }

    public Map<String, AAM> getAvailableAAMs() {
        return availableAAMs;
    }
}
