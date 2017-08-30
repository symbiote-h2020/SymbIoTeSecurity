package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

public class AttributesMap {

    @JsonProperty("attributes")
    private Map<String, String> attributes = new HashMap<>();

    @JsonCreator
    public AttributesMap(@JsonProperty("attributes") Map<String, String> attributes) {
        this.attributes = attributes;
    }
    public Map<String, String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
    }

}
