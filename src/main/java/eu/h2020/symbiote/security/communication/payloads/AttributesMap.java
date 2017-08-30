package eu.h2020.symbiote.security.communication.payloads;

import java.util.HashMap;
import java.util.Map;

public class AttributesMap {

    private Map<String, String> attributes = new HashMap<>();

    public AttributesMap(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    public AttributesMap() {
        //needed to create JSON
        //needed to create JSON
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
    }

}
