package eu.h2020.symbiote.security.communication.payloads;

import java.util.HashMap;
import java.util.Map;

public class LocalUsersAttributesMap {

    private Map<String, String> attributes = new HashMap<>();

    public LocalUsersAttributesMap(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
    }

}
